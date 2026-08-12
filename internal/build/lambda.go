package build

import (
	"github.com/AWSHound/AWSHound/internal/graph"
	"github.com/AWSHound/AWSHound/internal/model"
	"github.com/AWSHound/AWSHound/internal/store"
)

// LambdaNodes emits the account's AWS_LambdaFunction nodes — the Go port of
// AWSHound's LambdaFunctionNodeParser (core/graph/nodes/awslambda.py). One node per
// function, keyed by its ARN, with the exact property set (and insertion order) the
// Python parser produces. Functions without an ARN are skipped (the Python parser's
// early continue). LambdaFunctionList returns functions in ARN order, so the output
// is diff-stable.
//
// The "name" is "<account>:<function name>". memory_size and timeout carry the
// parser's defaults (128 / 3) when a re-ingested blob omits them; code_size defaults
// to 0. has_function_url / is_publicly_accessible are derived from the URL config
// (public means an AuthType of "NONE"). description, function_url(+auth type),
// kms_key_arn, layers, resource_policy, and tags are emitted only when present,
// matching the Python parser's `if x:` guards. layers and tags are JSON-encoded with
// Go's compact separators (the same convention as the sibling KMS/SSM/S3 node
// parsers); resource_policy is passed through verbatim as the raw policy string the
// collector captured (Python's str(policy) branch).
func LambdaNodes(a *store.Account) []*graph.Node {
	accountID := a.ID

	var nodes []*graph.Node
	for _, fn := range a.LambdaFunctionList() {
		if fn.FunctionArn == "" {
			continue
		}

		region := fn.Region
		if region == "" {
			region = "us-east-1"
		}

		urlConfig := fn.FunctionUrlConfig
		hasURL := urlConfig != nil
		isPublic := urlConfig != nil && urlConfig.AuthType == "NONE"

		n := graph.NewNode(fn.FunctionArn, graph.KindLambdaFunction)
		n.Set("name", accountID+":"+fn.FunctionName)
		n.Set("arn", fn.FunctionArn)
		n.Set("account_id", accountID)
		n.Set("region", region)
		n.Set("runtime", fn.Runtime)
		n.Set("handler", fn.Handler)
		n.Set("role_arn", fn.Role)
		n.Set("code_size", fn.CodeSize)
		n.Set("memory_size", lambdaMemorySizeOr(fn.MemorySize))
		n.Set("timeout", lambdaTimeoutOr(fn.Timeout))
		n.Set("last_modified", fn.LastModified)
		n.Set("has_function_url", hasURL)
		n.Set("is_publicly_accessible", isPublic)

		if fn.Description != "" {
			n.Set("description", fn.Description)
		}
		if urlConfig != nil {
			n.Set("function_url", urlConfig.FunctionUrl)
			n.Set("function_url_auth_type", urlConfig.AuthType)
		}
		if fn.KMSKeyArn != "" {
			n.Set("kms_key_arn", fn.KMSKeyArn)
		}
		if len(fn.Layers) > 0 {
			n.Set("layers", jsonProp(lambdaLayerARNs(fn.Layers)))
		}
		if fn.Policy != "" {
			n.Set("resource_policy", fn.Policy)
		}
		if len(fn.Tags) > 0 {
			n.Set("tags", jsonProp(fn.Tags))
		}

		nodes = append(nodes, n)
	}

	return nodes
}

// lambdaLayerARNs extracts the non-empty layer ARNs from a function's layers, in
// order. Mirrors the Python parser's [layer["Arn"] for layer in layers if
// layer["Arn"]]. Returns a non-nil (possibly empty) slice so the JSON encoding is
// "[]" rather than "null" when a layer set carries no ARNs — matching json.dumps([]).
func lambdaLayerARNs(layers []model.LambdaLayer) []string {
	out := make([]string, 0, len(layers))
	for _, l := range layers {
		if l.Arn != "" {
			out = append(out, l.Arn)
		}
	}
	return out
}

// lambdaMemorySizeOr mirrors func.get("MemorySize", 128). Lambda memory is always
// >= 128, so a zero value means the field was absent from a re-ingested blob and the
// parser default of 128 applies — the same zero-means-default convention the sibling
// SSM node parser uses for a parameter's version.
func lambdaMemorySizeOr(memorySize int) int {
	if memorySize == 0 {
		return 128
	}
	return memorySize
}

// lambdaTimeoutOr mirrors func.get("Timeout", 3). Lambda timeouts are always >= 1, so
// a zero value means the field was absent and the parser default of 3 applies.
func lambdaTimeoutOr(timeout int) int {
	if timeout == 0 {
		return 3
	}
	return timeout
}
