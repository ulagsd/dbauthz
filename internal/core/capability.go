package core

import "fmt"

// Support states how well an engine can express a given kind of control.
type Support int

const (
	// SupportNone means the engine has no way to express this.
	SupportNone Support = iota
	// SupportSubstitute means it is expressible only through a managed
	// construct that is not the engine's own primitive, such as a
	// security-barrier view standing in for row-level security. Always
	// recorded in the plan, never silent.
	SupportSubstitute
	// SupportNative means the engine has a first-class primitive for this.
	SupportNative
)

func (s Support) String() string {
	switch s {
	case SupportNone:
		return "none"
	case SupportSubstitute:
		return "substitute"
	case SupportNative:
		return "native"
	}
	return fmt.Sprintf("support(%d)", int(s))
}

// Capabilities is the probed profile of one target.
//
// It is always read from a live connection, never inferred from the engine
// name: the same engine differs by major version, by edition (Snowflake
// masking is Enterprise-only), and by managed provider (RDS has no true
// superuser). Treating "postgres" as a capability set is how a tool ends up
// silently under-enforcing on a variant it never tested.
type Capabilities struct {
	Engine  string // canonical engine id, e.g. "postgres"
	Version string // server version as reported
	Edition string // engine-specific tier, empty when not applicable
	Flavor  string // managed variant: "rds", "aurora", "cloudsql", "neon", ...

	// Levels the engine's object hierarchy actually implements.
	Levels LevelSet

	ColumnGrants Support
	RowFilters   Support
	Masking      Support

	// NativeDeny reports a persistent deny primitive that outranks grants.
	// Only SQL Server has one; the solver never relies on it.
	NativeDeny bool

	// FutureGrants reports an engine-native way to cover objects that do not
	// exist yet: ALTER DEFAULT PRIVILEGES, Snowflake future grants. Without
	// it, new-object coverage depends on the reconcile interval.
	FutureGrants bool

	// TransactionalDDL reports whether a failed apply rolls back cleanly.
	// When false, statement ordering must guarantee the fail-safe property on
	// its own, because there is no undo.
	TransactionalDDL bool

	// Superuser reports whether the connected principal can manage every role
	// in scope. Managed providers routinely say no.
	Superuser bool

	// Notes carries provider-specific caveats surfaced to the operator, such
	// as "rds_superuser cannot alter roles it does not own".
	Notes []string
}

// Supports reports whether a level is part of this engine's hierarchy.
func (c Capabilities) Supports(l Level) bool { return c.Levels.Has(l) }

// CanExpress reports whether the target can carry the given grant natively or
// by substitution, and names the first capability that falls short.
//
// This is the single check standing between a policy and silent
// under-enforcement, so it is deliberately conservative: anything it cannot
// positively confirm is reported as unsupported.
func (c Capabilities) CanExpress(g Grant) (Support, string) {
	worst := SupportNative
	limit := ""

	note := func(s Support, what string) {
		if s < worst {
			worst, limit = s, what
		}
	}

	if g.Columns != nil && !g.Columns.All {
		if !g.Action.ColumnScoped() {
			return SupportNone, "column-scoped " + string(g.Action)
		}
		note(c.ColumnGrants, "column grants")
	}
	if g.RowFilter != nil {
		note(c.RowFilters, "row filters")
	}
	if g.Mask != nil {
		note(c.Masking, "masking")
	}
	leaf, ok := g.Resource.Leaf()
	if !ok {
		return SupportNone, "empty resource path"
	}
	if l := g.Resource.Depth(); !c.Supports(l) {
		return SupportNone, l.String() + "-level resources"
	}
	// Checked on the leaf kind, not just its level: a sequence and a table
	// share a level but accept different privileges.
	if !g.Action.ValidFor(leaf.Kind) {
		return SupportNone, string(g.Action) + " on a " + string(leaf.Kind)
	}
	return worst, limit
}

// MarshalJSON renders support as its name, so an API response reads as
// "native" rather than 2.
func (s Support) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// MarshalJSON renders the level set as a list of level names.
func (s LevelSet) MarshalJSON() ([]byte, error) {
	out := []byte{'['}
	for i, l := range s.Levels() {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, '"')
		out = append(out, l.String()...)
		out = append(out, '"')
	}
	return append(out, ']'), nil
}
