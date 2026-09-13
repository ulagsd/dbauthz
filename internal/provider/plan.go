package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ulagsd/db-iam/internal/core"
)

// Risk classifies what a statement can cost if it is wrong.
type Risk int

const (
	// RiskSafe widens nothing and destroys nothing.
	RiskSafe Risk = iota
	// RiskGrant widens access.
	RiskGrant
	// RiskRevoke narrows access, which can break a working application.
	RiskRevoke
	// RiskDestructive drops or replaces an object.
	RiskDestructive
)

func (r Risk) String() string {
	switch r {
	case RiskGrant:
		return "grant"
	case RiskRevoke:
		return "revoke"
	case RiskDestructive:
		return "destructive"
	}
	return "safe"
}

// Statement is one engine statement with the context needed to review it.
type Statement struct {
	// SQL is what executes. It may embed a secret, because DDL cannot take
	// bind parameters for passwords or identifiers.
	SQL string

	// Display is what a human sees: the plan view, the API response, the audit
	// record. When a statement carries a secret this holds the same SQL with
	// the secret replaced, so reviewing a plan never means reading one.
	// Empty means SQL is safe to show as-is.
	Display string

	Risk   Risk
	Reason string   // why this statement exists, in the operator's terms
	Origin []string // policy statement ids

	// Substituted marks a statement standing in for a primitive the engine
	// lacks, such as a view replacing row-level security. Never silent: the
	// plan renders these distinctly and the audit record keeps them.
	Substituted bool
}

// Redacted returns the reviewable form of the statement, which is Display when
// the statement carries a secret and SQL otherwise.
//
// Everything that shows a statement to a human or writes one to a record goes
// through this. Reaching for .SQL outside the apply path is the bug.
func (s Statement) Redacted() string {
	if s.Display != "" {
		return s.Display
	}
	return s.SQL
}

// StatementSet is the compiled, not-yet-ordered output of Compile.
type StatementSet struct {
	Target     core.TargetRef
	Statements []Statement

	// Substitutions summarises every place the engine could not use its own
	// primitive, for display above the plan.
	Substitutions []string
}

// Plan is an ordered, classified, content-addressed change.
type Plan struct {
	ID         string
	Target     core.TargetRef
	Statements []Statement
	CreatedAt  time.Time

	// SnapshotVersion pins the observed state the plan was computed against.
	// Apply rejects the plan if the target has moved past it, so an approved
	// plan can never be applied to a database it was not reviewed against.
	SnapshotVersion int64

	// Hash covers the statements and the snapshot version. Approval is
	// recorded against this value.
	Hash string

	// CreatedRoles names the principals this plan brings into existence, so
	// Verify can confirm they are really there rather than trusting that the
	// statements returned no error.
	CreatedRoles []string
}

// MaxRisk reports the highest risk in the plan, which decides whether
// approval is required.
func (p *Plan) MaxRisk() Risk {
	worst := RiskSafe
	for _, s := range p.Statements {
		if s.Risk > worst {
			worst = s.Risk
		}
	}
	return worst
}

// Empty reports whether the plan is a no-op.
func (p *Plan) Empty() bool { return len(p.Statements) == 0 }

// ComputeHash sets Hash from the plan's content. Any edit to the statements
// or the pinned snapshot changes it, which is what makes an approval
// non-transferable to a different plan.
func (p *Plan) ComputeHash() string {
	h := sha256.New()
	// hash.Hash never returns a write error, so these are checked once here
	// rather than at every call.
	hf := func(format string, args ...any) { _, _ = fmt.Fprintf(h, format, args...) }

	// The version prefix means a future change to what the hash covers cannot
	// be mistaken for an unchanged plan.
	hf("v1\n%s\n%d\n", p.Target.ID, p.SnapshotVersion)
	for _, s := range p.Statements {
		hf("%d\x00%s\x00%t\n", s.Risk, s.SQL, s.Substituted)
	}
	p.Hash = hex.EncodeToString(h.Sum(nil))
	return p.Hash
}

// Render produces a reviewable plan, grouped so the dangerous statements are
// impossible to miss.
func (p *Plan) Render() string {
	// strings.Builder never returns an error, so the writes below are
	// deliberately unchecked via this helper.
	var b strings.Builder
	pf := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	pf("Plan %s for %s\n", p.ID, p.Target)
	pf("  snapshot %d · %d statements · max risk %s\n\n",
		p.SnapshotVersion, len(p.Statements), p.MaxRisk())
	for _, risk := range []Risk{RiskDestructive, RiskRevoke, RiskGrant, RiskSafe} {
		var group []Statement
		for _, s := range p.Statements {
			if s.Risk == risk {
				group = append(group, s)
			}
		}
		if len(group) == 0 {
			continue
		}
		pf("%s (%d)\n", strings.ToUpper(risk.String()), len(group))
		for _, s := range group {
			marker := "  "
			if s.Substituted {
				marker = " ~" // stands in for a primitive the engine lacks
			}
			pf("%s %s\n", marker, s.Redacted())
			if s.Reason != "" {
				pf("     -- %s\n", s.Reason)
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// ApplyResult records what actually happened, statement by statement, because
// on an engine without transactional DDL a partial apply is a real outcome
// that has to be reported rather than retried blindly.
type ApplyResult struct {
	PlanHash  string
	StartedAt time.Time
	EndedAt   time.Time
	Executed  int
	Failed    int
	Errors    []StatementError

	// Indeterminate marks an apply that lost its connection partway through a
	// non-transactional sequence. The target's real state is unknown until a
	// verified reconcile clears it, and it must not be retried automatically.
	Indeterminate bool
}

// StatementError pins a failure to the statement that caused it. SQL holds the
// redacted form: an error is the most likely thing to be pasted into a ticket.
type StatementError struct {
	Index int
	SQL   string
	Err   string
}

// VerifyResult reports whether observed state converged on the plan's intent.
type VerifyResult struct {
	Converged  bool
	Divergence []string
}

// Snapshot is one provider's observed view of a target.
type Snapshot struct {
	Target  core.TargetRef
	Version int64
	TakenAt time.Time
	Cursor  Cursor

	Principals []ObservedPrincipal
	Objects    []ObservedObject
	Grants     []ObservedGrant
}

// ObservedPrincipal is a role or user that exists on the target.
type ObservedPrincipal struct {
	Name     string
	Managed  bool // created by db-iam, identified by ManagedPrefix
	Login    bool
	Inherit  bool
	MemberOf []string
}

// ObservedObject is a grantable object that exists on the target.
type ObservedObject struct {
	Path    core.ResourcePath
	Owner   string
	Columns []string
	RLS     bool // row-level security enabled
}

// ObservedGrant is a privilege that exists on the target.
type ObservedGrant struct {
	Grantee string
	Action  core.Action
	Path    core.ResourcePath
	Columns []string // empty means the whole object

	// Implicit marks a privilege the grantee holds by owning the object rather
	// than by an explicit grant. Revoking one breaks the owner, so no
	// reconcile mode may propose it.
	Implicit bool
}
