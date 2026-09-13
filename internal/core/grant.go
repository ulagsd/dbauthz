package core

import (
	"fmt"
	"sort"
	"strings"
)

// PrincipalKind distinguishes the sorts of identity a grant can name.
type PrincipalKind string

// The kinds of identity a grant can name.
const (
	PrincipalHuman   PrincipalKind = "user"
	PrincipalService PrincipalKind = "service"
	PrincipalGroup   PrincipalKind = "group"
)

// PrincipalRef identifies a principal. By the time a PrincipalRef appears in a
// Grant it is always concrete: group membership is expanded by the solver, so
// providers never resolve identity themselves.
type PrincipalRef struct {
	Kind PrincipalKind
	ID   string // stable internal id
	Name string // display name, for rendering plans and audit
}

func (p PrincipalRef) String() string { return string(p.Kind) + ":" + p.Name }

// ColumnSet narrows an action to specific columns.
//
// All is the common case and is not the same as listing every current column:
// a list is fixed at plan time and silently excludes columns added later,
// which fails safe, whereas All keeps tracking the table. Providers must
// preserve that distinction.
type ColumnSet struct {
	All  bool
	Name []string // meaningful only when All is false
}

// AllColumns returns a ColumnSet covering the whole object.
func AllColumns() *ColumnSet { return &ColumnSet{All: true} }

// NamedColumns returns a ColumnSet over an explicit, de-duplicated list.
func NamedColumns(names ...string) *ColumnSet {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if _, dup := seen[n]; dup {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return &ColumnSet{Name: out}
}

// Intersect narrows c to also satisfy other. Used when several allow
// statements grant overlapping column sets for the same action.
func (c *ColumnSet) Intersect(other *ColumnSet) *ColumnSet {
	switch {
	case c == nil || c.All:
		return other
	case other == nil || other.All:
		return c
	}
	keep := map[string]struct{}{}
	for _, n := range other.Name {
		keep[n] = struct{}{}
	}
	var out []string
	for _, n := range c.Name {
		if _, ok := keep[n]; ok {
			out = append(out, n)
		}
	}
	return &ColumnSet{Name: out}
}

// Remove returns c without the named columns, materialising All into an
// explicit list first. This is how a column-level Deny is expressed on engines
// that have no deny: the grant is narrowed rather than removed.
func (c *ColumnSet) Remove(available []string, drop ...string) *ColumnSet {
	base := available
	if c != nil && !c.All {
		base = c.Name
	}
	dropped := map[string]struct{}{}
	for _, d := range drop {
		dropped[d] = struct{}{}
	}
	out := make([]string, 0, len(base))
	for _, n := range base {
		if _, gone := dropped[n]; !gone {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return &ColumnSet{Name: out}
}

// Empty reports whether the set selects nothing, which means the grant should
// be dropped entirely rather than emitted as a zero-column privilege.
func (c *ColumnSet) Empty() bool { return c != nil && !c.All && len(c.Name) == 0 }

func (c *ColumnSet) String() string {
	if c == nil || c.All {
		return "*"
	}
	return "(" + strings.Join(c.Name, ", ") + ")"
}

// MaskSpec describes how a column's values are obscured.
type MaskSpec struct {
	Kind    string // "null", "constant", "hash", "partial"
	Value   string // replacement for "constant"
	Keep    int    // trailing characters kept for "partial"
	Columns []string
}

// Grant is one fully resolved permission.
//
// Every Grant in an EffectivePermissionSet is concrete: the resource names a
// real object, the principal is a real identity, deny has already been
// subtracted, and any static condition has already been evaluated. A provider
// receiving a Grant has only to express it or refuse.
type Grant struct {
	Principal PrincipalRef
	Action    Action
	Resource  ResourcePath
	Columns   *ColumnSet // nil means all columns
	RowFilter Predicate  // nil means no filter
	Mask      *MaskSpec  // nil means no masking

	// Origin records the policy statement ids this grant came from, so a plan
	// can explain itself and a refusal can name the statement to fix.
	Origin []string
}

// Key identifies the (principal, action, resource) triple a grant applies to.
// Grants sharing a key are merged by the solver.
func (g Grant) Key() string {
	return string(g.Principal.Kind) + "\x00" + g.Principal.ID + "\x00" +
		string(g.Action) + "\x00" + g.Resource.String()
}

func (g Grant) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s on %s", g.Principal, g.Action, g.Resource)
	if g.Columns != nil && !g.Columns.All {
		b.WriteString(" columns " + g.Columns.String())
	}
	if g.RowFilter != nil {
		b.WriteString(" where " + g.RowFilter.String())
	}
	if g.Mask != nil {
		b.WriteString(" masked " + g.Mask.Kind)
	}
	return b.String()
}

// TargetRef identifies a managed database instance.
type TargetRef struct {
	ID     string
	Name   string
	Engine string
}

func (t TargetRef) String() string { return t.Name + " (" + t.Engine + ")" }

// EffectivePermissionSet is the boundary between the engine-neutral half of
// db-iam and the provider half. Everything upstream of it is portable;
// everything downstream is engine-specific.
//
// Two invariants hold on every value of this type, and providers depend on
// both:
//
//   - No globs remain. Every Grant names a concrete object that existed in the
//     catalog snapshot the set was solved against.
//   - No deny remains. Providers receive only positive grants and never reason
//     about deny semantics, which is what keeps adding an engine tractable.
type EffectivePermissionSet struct {
	Target TargetRef

	// SnapshotVersion is the catalog version this set was solved against.
	// An apply whose target has moved past it is rejected and re-planned.
	SnapshotVersion int64

	Grants []Grant
}

// Sort orders grants deterministically so that plans, hashes and golden test
// files are stable across runs.
func (e *EffectivePermissionSet) Sort() {
	sort.SliceStable(e.Grants, func(i, j int) bool {
		return e.Grants[i].Key() < e.Grants[j].Key()
	})
}

// Principals lists the distinct principals in the set, in stable order.
func (e *EffectivePermissionSet) Principals() []PrincipalRef {
	seen := map[string]PrincipalRef{}
	for _, g := range e.Grants {
		seen[g.Principal.ID] = g.Principal
	}
	out := make([]PrincipalRef, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Deferred returns the grants carrying a session-dependent row filter. These
// are the grants that require an engine-native runtime construct, and the
// first thing a provider checks against its capability profile.
func (e *EffectivePermissionSet) Deferred() []Grant {
	var out []Grant
	for _, g := range e.Grants {
		if g.RowFilter != nil && IsDeferred(g.RowFilter) {
			out = append(out, g)
		}
	}
	return out
}
