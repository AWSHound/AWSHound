package collect

import (
	"context"
	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/AWSHound/AWSHound/internal/model"
)

// KMSCollector fetches AWS KMS key data (region-scoped; see the package doc). Per
// region, Fetch lists aliases and keys, then enriches every key with its readable
// policy and grants. Editable-only tags and rotation status remain restricted to
// customer-managed keys. A key whose DescribeKey fails is dropped; each enrichment
// sub-call falls back to empty/nil on error.
type KMSCollector struct{}

// Service returns the collector's service identifier.
func (KMSCollector) Service() string { return "kms" }

// Fetch collects every KMS key across the account's enabled regions. It mirrors
// KMSCollector.fetch: pass one lists aliases (grouped by target key) and keys per
// region; pass two enriches each key with readable policy/grants and adds tags/
// rotation only for customer-managed keys.
func (KMSCollector) Fetch(ctx context.Context, s *Session) (any, error) {
	accountID, err := s.AccountID(ctx)
	if err != nil {
		return nil, err
	}

	perRegion, err := fanRegions(ctx, s, "kms", func(ctx context.Context, region string) []model.KMSKey {
		client := kms.NewFromConfig(s.regionCfg(region))

		// Per-region alias map: target key id -> its aliases. Best-effort; a key
		// with no aliases simply gets an empty list.
		aliasMap := kmsListAliases(ctx, client)

		var keys []model.KMSKey
		keyPager := kms.NewListKeysPaginator(client, &kms.ListKeysInput{})
		for keyPager.HasMorePages() {
			page, pageErr := keyPager.NextPage(ctx)
			if pageErr != nil {
				// Cannot list keys here (e.g. region disabled / denied); skip the
				// rest of this region, matching the Python region-skip.
				break
			}
			for _, entry := range page.Keys {
				keyID := aws.ToString(entry.KeyId)
				if keyID == "" {
					continue
				}
				key := kmsDescribeKey(ctx, client, keyID, aws.ToString(entry.KeyArn), region)
				if key == nil {
					continue
				}

				aliases := aliasMap[key.KeyId]
				if aliases == nil {
					aliases = []model.KMSAlias{}
				}
				key.Aliases = aliases

				kmsEnrichKey(ctx, client, key)
				keys = append(keys, *key)
			}
		}
		return keys
	})
	if err != nil {
		return nil, err
	}

	var keys []model.KMSKey
	for _, r := range perRegion {
		keys = append(keys, r...)
	}
	return &model.KMSData{AccountId: accountID, Keys: keys}, nil
}

// kmsListAliases lists all aliases in the region and groups them by their target
// key id. Ports pass one's alias_map build; alias listing is best-effort (a failure
// yields an empty map).
func kmsListAliases(ctx context.Context, client *kms.Client) map[string][]model.KMSAlias {
	aliasMap := map[string][]model.KMSAlias{}
	pager := kms.NewListAliasesPaginator(client, &kms.ListAliasesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, a := range page.Aliases {
			targetKeyID := aws.ToString(a.TargetKeyId)
			if targetKeyID == "" {
				continue
			}
			aliasMap[targetKeyID] = append(aliasMap[targetKeyID], model.KMSAlias{
				AliasName: aws.ToString(a.AliasName),
				AliasArn:  aws.ToString(a.AliasArn),
			})
		}
	}
	return aliasMap
}

// kmsDescribeKey describes a key and returns its normalized metadata, or nil when
// the describe fails (the key is then dropped). Ports KMSCollector._describe_key.
func kmsDescribeKey(ctx context.Context, client *kms.Client, keyID, keyArn, region string) *model.KMSKey {
	out, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(keyID)})
	if err != nil || out.KeyMetadata == nil {
		return nil
	}
	m := out.KeyMetadata
	// Grants/Tags default to empty (not nil) so an AWS-managed key — which skips the
	// customer-managed enrichment below — still serializes them as [] rather than null.
	return &model.KMSKey{
		KeyId:        kmsStringOr(m.KeyId, keyID),
		Arn:          kmsStringOr(m.Arn, keyArn),
		Region:       region,
		KeyState:     string(m.KeyState),
		KeyManager:   string(m.KeyManager),
		KeySpec:      string(m.KeySpec),
		KeyUsage:     string(m.KeyUsage),
		Origin:       string(m.Origin),
		Description:  aws.ToString(m.Description),
		CreationDate: formatTime(m.CreationDate),
		Enabled:      m.Enabled,
		MultiRegion:  aws.ToBool(m.MultiRegion),
		Grants:       []model.KMSGrant{},
		Tags:         []model.KMSTag{},
	}
}

// kmsEnrichmentClient is the readable/editable subset used after DescribeKey.
// Keeping it as an interface makes the key-manager behavior independently testable.
type kmsEnrichmentClient interface {
	GetKeyPolicy(context.Context, *kms.GetKeyPolicyInput, ...func(*kms.Options)) (*kms.GetKeyPolicyOutput, error)
	ListGrants(context.Context, *kms.ListGrantsInput, ...func(*kms.Options)) (*kms.ListGrantsOutput, error)
	ListResourceTags(context.Context, *kms.ListResourceTagsInput, ...func(*kms.Options)) (*kms.ListResourceTagsOutput, error)
	GetKeyRotationStatus(context.Context, *kms.GetKeyRotationStatusInput, ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
}

// kmsEnrichKey collects readable policy/grant data for every key, while keeping
// tag and rotation calls to customer-managed keys.
func kmsEnrichKey(ctx context.Context, client kmsEnrichmentClient, key *model.KMSKey) {
	key.KeyPolicy, key.KeyPolicyKnown = kmsGetKeyPolicy(ctx, client, key.KeyId)
	key.Grants = kmsListGrants(ctx, client, key.KeyId)
	if key.KeyManager == "CUSTOMER" {
		key.Tags = kmsListTags(ctx, client, key.KeyId)
		key.KeyRotationEnabled = kmsRotationStatus(ctx, client, key)
	}
}

// kmsGetKeyPolicy fetches the "default" key policy as raw JSON. known is false
// when it is absent, denied, or invalid, allowing evaluation to distinguish
// unknown authorization from a policy that was successfully collected.
func kmsGetKeyPolicy(ctx context.Context, client kmsEnrichmentClient, keyID string) (json.RawMessage, bool) {
	out, err := client.GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{
		KeyId:      aws.String(keyID),
		PolicyName: aws.String("default"),
	})
	if err != nil {
		return nil, false
	}
	policy := aws.ToString(out.Policy)
	if policy == "" || !json.Valid([]byte(policy)) {
		return nil, false
	}
	return json.RawMessage(policy), true
}

// kmsListGrants lists every grant on a key. Ports KMSCollector._list_grants; a
// failure returns whatever was collected so far (starting empty).
func kmsListGrants(ctx context.Context, client kmsEnrichmentClient, keyID string) []model.KMSGrant {
	grants := []model.KMSGrant{}
	pager := kms.NewListGrantsPaginator(client, &kms.ListGrantsInput{KeyId: aws.String(keyID)})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, g := range page.Grants {
			grants = append(grants, model.KMSGrant{
				GrantId:           aws.ToString(g.GrantId),
				GranteePrincipal:  aws.ToString(g.GranteePrincipal),
				RetiringPrincipal: aws.ToString(g.RetiringPrincipal),
				Operations:        kmsGrantOperations(g.Operations),
				Constraints:       kmsGrantConstraints(g.Constraints),
				IssuingAccount:    aws.ToString(g.IssuingAccount),
				CreationDate:      formatTime(g.CreationDate),
			})
		}
	}
	return grants
}

// kmsListTags lists a key's resource tags. Ports KMSCollector._list_tags.
func kmsListTags(ctx context.Context, client kmsEnrichmentClient, keyID string) []model.KMSTag {
	tags := []model.KMSTag{}
	pager := kms.NewListResourceTagsPaginator(client, &kms.ListResourceTagsInput{KeyId: aws.String(keyID)})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			break
		}
		for _, t := range page.Tags {
			tags = append(tags, model.KMSTag{
				TagKey:   aws.ToString(t.TagKey),
				TagValue: aws.ToString(t.TagValue),
			})
		}
	}
	return tags
}

// kmsRotationStatus returns the key's rotation flag, but only for customer-managed
// symmetric ENCRYPT_DECRYPT keys (the only keys for which rotation status is
// meaningful); otherwise nil. Ports KMSCollector._get_rotation_status.
func kmsRotationStatus(ctx context.Context, client kmsEnrichmentClient, key *model.KMSKey) *bool {
	if key.KeySpec != "SYMMETRIC_DEFAULT" || key.KeyUsage != "ENCRYPT_DECRYPT" {
		return nil
	}
	out, err := client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: aws.String(key.KeyId)})
	if err != nil {
		return nil
	}
	enabled := out.KeyRotationEnabled
	return &enabled
}

// kmsGrantOperations converts the SDK's typed grant-operation enums to plain
// strings, matching the boto3 list-of-strings the Python collector stores.
func kmsGrantOperations(ops []kmstypes.GrantOperation) []string {
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		out = append(out, string(op))
	}
	return out
}

// kmsGrantConstraints maps the SDK grant constraints to the collected shape,
// yielding the empty object {} when there are none (Python's {} default).
func kmsGrantConstraints(c *kmstypes.GrantConstraints) model.KMSGrantConstraints {
	if c == nil {
		return model.KMSGrantConstraints{}
	}
	return model.KMSGrantConstraints{
		EncryptionContextEquals: c.EncryptionContextEquals,
		EncryptionContextSubset: c.EncryptionContextSubset,
	}
}

// kmsStringOr dereferences p, falling back to def when p is nil — the analogue of
// the Python collector's metadata.get(field, fallback) for KeyId/Arn.
func kmsStringOr(p *string, def string) string {
	if p != nil {
		return *p
	}
	return def
}
