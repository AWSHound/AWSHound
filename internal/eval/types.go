// Package eval ports AWSHound's IAM policy evaluator — the correctness-critical
// core that decides whether an attack edge exists (whether a principal is
// allowed an action on a resource, and whether a role's trust policy admits a
// principal). It compiles AWS policy documents into bundled grants and combines
// a principal's identity policies, permissions boundary, SCPs, and RCPs into
// queryable effective permissions.
//
// These value types are ported field-for-field from AWSHound's Python
// implementation: core/evaluation/iam_policy/model.py (Effect, Grant,
// CompiledPolicy, EffectiveStatement, EffectivePermissions), core/models/types.py
// (PermissionOutcome, PermissionCheckResult, TrustCheckResult), and
// core/evaluation/conditions/resolution.py (the Kleene tristate). The IAM
// policy-document AST and its parser live in policy.go; the action catalog in
// catalog.go.
package eval

// Effect is a policy statement's effect. Ported from iam_policy/model.py Effect;
// the string values match the raw "Effect" field of a policy statement.
type Effect string

const (
	EffectAllow Effect = "Allow"
	EffectDeny  Effect = "Deny"
)

// PermissionOutcome explains why a permission check resolved the way it did.
// Ported from core/models/types.py PermissionOutcome (a StrEnum).
//
// AWS produces semantically distinct "no" outcomes that matter for attack-path
// analysis: an explicit deny is a durable control (bypass means editing a
// policy), an implicit deny means nothing grants it (bypass means adding a
// permission), and a ceiling clip means an identity grant exists but a boundary
// or SCP/RCP guardrail removes it (bypass means changing the guardrail).
//
// OutcomeDeniedByRCP has no counterpart in the Python enum, which folds RCP
// denials into DENIED_BY_SCP (its single org-guardrail bucket, see
// policy_evaluator._classify_deny). The Go port gives Resource Control Policies
// their own outcome so attack-path enrichment can name the exact blocking
// guardrail kind.
type PermissionOutcome string

const (
	OutcomeAllowed          PermissionOutcome = "ALLOWED"
	OutcomeExplicitDeny     PermissionOutcome = "EXPLICIT_DENY"
	OutcomeImplicitDeny     PermissionOutcome = "IMPLICIT_DENY"
	OutcomeDeniedByBoundary PermissionOutcome = "DENIED_BY_BOUNDARY"
	OutcomeDeniedBySCP      PermissionOutcome = "DENIED_BY_SCP"
	OutcomeDeniedByRCP      PermissionOutcome = "DENIED_BY_RCP"
)

// PermissionCheckResult is the result of checking whether a principal can
// perform an action on a resource. Ported from core/models/types.py.
//
// Allowed and Denied keep their exact prior meaning; Outcome is additive
// attack-path enrichment. A zero-value Outcome ("") should be read as
// OutcomeImplicitDeny, the Python dataclass default. BlockingSource is the ARN
// of the policy/guardrail responsible for a deny outcome (the explicit-deny
// source, or the blocking boundary/SCP/RCP), or "" when not applicable (the
// Python None).
type PermissionCheckResult struct {
	Allowed        bool
	Denied         bool
	Conditions     []map[string]any
	AllowSources   []string
	DenySources    []string
	Outcome        PermissionOutcome
	BlockingSource string
}

// TrustCheckResult is the result of checking whether a role's trust policy
// allows a principal. Ported from core/models/types.py.
type TrustCheckResult struct {
	Trusted    bool
	Conditions []map[string]any
}

// Resolution is the tristate result of statically evaluating a Condition (block,
// key, or value). Ported from conditions/resolution.py.
//
// ResolutionUnknown means the evaluator could not statically determine the
// outcome — typically because a required context key is unknowable (e.g.
// aws:SourceIp) or because the relevant data was not ingested. It is the zero
// value, so an unset Resolution defaults to the conservative "unknown".
type Resolution int

const (
	ResolutionUnknown Resolution = iota
	ResolutionTrue
	ResolutionFalse
)

// String returns the lowercase label matching the Python enum's value.
func (r Resolution) String() string {
	switch r {
	case ResolutionTrue:
		return "true"
	case ResolutionFalse:
		return "false"
	default:
		return "unknown"
	}
}

// And is three-valued AND. FALSE dominates; UNKNOWN beats TRUE. Ported from
// conditions/resolution.py kleene_and.
func (a Resolution) And(b Resolution) Resolution {
	if a == ResolutionFalse || b == ResolutionFalse {
		return ResolutionFalse
	}
	if a == ResolutionUnknown || b == ResolutionUnknown {
		return ResolutionUnknown
	}
	return ResolutionTrue
}

// Or is three-valued OR. TRUE dominates; UNKNOWN beats FALSE. Ported from
// conditions/resolution.py kleene_or.
func (a Resolution) Or(b Resolution) Resolution {
	if a == ResolutionTrue || b == ResolutionTrue {
		return ResolutionTrue
	}
	if a == ResolutionUnknown || b == ResolutionUnknown {
		return ResolutionUnknown
	}
	return ResolutionFalse
}

// Not is three-valued NOT. UNKNOWN is its own negation. Ported from
// conditions/resolution.py kleene_not.
func (a Resolution) Not() Resolution {
	switch a {
	case ResolutionTrue:
		return ResolutionFalse
	case ResolutionFalse:
		return ResolutionTrue
	default:
		return ResolutionUnknown
	}
}

// ActionSet is an unordered set of IAM action strings — the Go equivalent of the
// frozenset[str] the Python engine bundles into each Grant. Set algebra
// (union/intersection/difference), used when the engine resolves complement
// grants and applies ceilings, belongs with the engine port, not here.
type ActionSet map[string]struct{}

// NewActionSet builds an ActionSet from the given actions.
func NewActionSet(actions ...string) ActionSet {
	s := make(ActionSet, len(actions))
	for _, a := range actions {
		s[a] = struct{}{}
	}
	return s
}

// Grant is one bundled (action-set, resource, condition, source) unit from a
// compiled policy. Ported from iam_policy/model.py Grant.
//
// Complement flips the meaning of Actions to exclusion: the grant then applies
// to every action EXCEPT those in Actions. It is the symbolic form for
// Action:"*" (complement of the empty set) and NotAction:[E] (complement of E),
// so the ~20k-action catalog is never materialized in a compiled grant. The
// engine keeps complements symbolic through lazy action lookup, so concrete
// indexes stay small. Complement=false is the ordinary
// "exactly these actions" grant.
//
// Resource and NotResource are nil when the statement omitted them (the Python
// None); a non-nil pointer holds the glob pattern (which may itself be "*").
// AWS treats Resource and NotResource as mutually exclusive within a statement.
// Condition is nil when the statement had none; otherwise it is the normalized
// operator->key->values block, which must hold in addition to the action and
// resource matching.
type Grant struct {
	Actions     ActionSet
	Resource    *string
	NotResource *string
	Condition   Condition
	Source      string
	Effect      Effect
	Complement  bool
}

// CompiledPolicy is a single policy document compiled to bundled grants
// (catalog-expanded). Ported from iam_policy/model.py CompiledPolicy.
type CompiledPolicy struct {
	Grants []Grant
}

// EffectiveStatement is a bundled statement in a principal's effective
// permissions (pattern-based). Ported from iam_policy/model.py
// EffectiveStatement. Its Actions set stays attached so compressed permissions
// can build only the action views the graph actually queries.
type EffectiveStatement struct {
	Actions     ActionSet
	Resource    *string
	NotResource *string
	Condition   Condition
	Source      string
	// Complement means Actions is the exclusion set: the statement applies to
	// every catalog action except those entries. Keeping this symbolic through
	// compression avoids expanding Action:"*" into one cached statement per AWS
	// action for every principal.
	Complement bool
	// IdentityScoped limits a complement deny to actions named by at least one
	// identity allow. The query layer tests its already-compact identity index,
	// avoiding both a materialized union and a retained per-grant scope slice.
	IdentityScoped bool
}

// EffectivePermissions is a principal's compact effective permission set. The
// field names identify the represented layer; each holds its logical statements
// once and compression builds action views lazily.
//
// AllowByAction and DenyByAction are the final, ceiling-baked indexes the query
// layer resolves. The remaining indexes are kept separately so the deny cause is
// recoverable at query time without a second evaluation pass:
// IdentityAllowByAction is what the identity policies alone granted
// (pre-ceiling), and the guardrail indexes are each guardrail's own permitted
// set (boundary as-is; SCP/RCP intersected across their attach levels). When a
// query is denied, comparing these tells a boundary/SCP/RCP clip apart from an
// implicit deny.
//
// HasBoundary/HasSCP/HasRCP record which guardrails were actually applied, so an
// absent guardrail (empty permitted set) is not mistaken for one that blocks
// everything. ScpAllowPermitsAll/RcpAllowPermitsAll flag a guardrail whose own
// permitted set is every action (e.g. only FullAWSAccess at every level),
// carried as a flag instead of a ~20k-entry index; deny-cause then treats it as
// covering any action without consulting the (intentionally empty) index.
type EffectivePermissions struct {
	AllowByAction         []*EffectiveStatement
	DenyByAction          []*EffectiveStatement
	IdentityAllowByAction []*EffectiveStatement
	BoundaryAllowByAction []*EffectiveStatement
	ScpAllowByAction      []*EffectiveStatement
	RcpAllowByAction      []*EffectiveStatement
	HasBoundary           bool
	HasSCP                bool
	HasRCP                bool
	ScpAllowPermitsAll    bool
	RcpAllowPermitsAll    bool
	// IdentityActionScope is the de-duplicated finite action selectors from the
	// identity policy. Complement denies consult it for the original implicit-vs-
	// explicit deny classification without retaining every resource grant.
	IdentityActionScope []ActionSet
}

// NewEffectivePermissions returns an EffectivePermissions with all six action
// indexes initialized to empty maps (matching the Python dataclass's
// default_factory=dict), so the engine can index into them without nil-map
// panics.
func NewEffectivePermissions() *EffectivePermissions {
	return &EffectivePermissions{}
}
