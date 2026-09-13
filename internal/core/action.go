package core

import (
	"fmt"
	"sort"
	"strings"
)

// Action is a canonical, engine-neutral verb.
//
// The vocabulary is deliberately the intersection of what mainstream engines
// express, not the union. An engine-specific privilege with no portable
// meaning does not become an Action; it is reached through a provider escape
// hatch instead. Widening this set is a breaking change to every provider.
type Action string

// The canonical action vocabulary. Adding to this set is a breaking change
// for every provider, so it stays at the intersection of what engines express.
const (
	ActionConnect   Action = "db:Connect"
	ActionUsage     Action = "db:Usage" // enter a schema, use a sequence
	ActionSelect    Action = "db:Select"
	ActionInsert    Action = "db:Insert"
	ActionUpdate    Action = "db:Update"
	ActionDelete    Action = "db:Delete"
	ActionTruncate  Action = "db:Truncate"
	ActionReference Action = "db:Reference"
	ActionTrigger   Action = "db:Trigger"
	ActionExecute   Action = "db:Execute"
	ActionCreate    Action = "db:Create"
	ActionAlter     Action = "db:Alter"
	ActionDrop      Action = "db:Drop"
	ActionTemporary Action = "db:Temporary"
)

// actionSpec records where an action may be attached and what it implies.
//
// Applicability is keyed on segment kind rather than hierarchy level, because
// level is too coarse to be safe: a sequence and a table are both LevelObject,
// yet USAGE is meaningful on one and meaningless on the other. Getting this
// wrong lets a nonsensical grant reach the provider instead of being rejected
// as the policy error it is.
type actionSpec struct {
	kinds map[SegmentKind]bool
	// columnScoped reports whether the action can be narrowed to a column
	// list. Only these four can, on every engine with column grants.
	columnScoped bool
	// mutating actions are classified as higher-risk when planning.
	mutating bool
}

func kinds(ks ...SegmentKind) map[SegmentKind]bool {
	m := make(map[SegmentKind]bool, len(ks))
	for _, k := range ks {
		m[k] = true
	}
	return m
}

// Object kinds that behave like a relation for privilege purposes.
var relationKinds = []SegmentKind{KindTable, KindView, KindCollection}

func withRelations(extra ...SegmentKind) []SegmentKind {
	return append(append([]SegmentKind{}, relationKinds...), extra...)
}

var actionSpecs = map[Action]actionSpec{
	ActionConnect: {kinds: kinds(KindTarget, KindDatabase)},
	// USAGE lets a principal enter a schema or read a sequence. It has no
	// meaning on a table, which is the distinction levels alone would lose.
	ActionUsage:     {kinds: kinds(KindSchema, KindSequence)},
	ActionSelect:    {kinds: kinds(withRelations(KindSequence, KindColumn, KindField)...), columnScoped: true},
	ActionInsert:    {kinds: kinds(withRelations(KindColumn, KindField)...), columnScoped: true, mutating: true},
	ActionUpdate:    {kinds: kinds(withRelations(KindSequence, KindColumn, KindField)...), columnScoped: true, mutating: true},
	ActionDelete:    {kinds: kinds(relationKinds...), mutating: true},
	ActionTruncate:  {kinds: kinds(KindTable), mutating: true},
	ActionReference: {kinds: kinds(withRelations(KindColumn, KindField)...), columnScoped: true},
	ActionTrigger:   {kinds: kinds(relationKinds...), mutating: true},
	ActionExecute:   {kinds: kinds(KindFunction, KindProcedure), mutating: false},
	ActionCreate:    {kinds: kinds(KindDatabase, KindSchema), mutating: true},
	ActionAlter: {kinds: kinds(withRelations(
		KindDatabase, KindSchema, KindSequence, KindFunction, KindProcedure)...), mutating: true},
	ActionDrop: {kinds: kinds(withRelations(
		KindDatabase, KindSchema, KindSequence, KindFunction, KindProcedure)...), mutating: true},
	ActionTemporary: {kinds: kinds(KindDatabase)},
}

// Known reports whether the action is part of the canonical vocabulary.
func (a Action) Known() bool { _, ok := actionSpecs[a]; return ok }

// ValidFor reports whether the action is meaningful on a kind of object.
func (a Action) ValidFor(k SegmentKind) bool {
	spec, ok := actionSpecs[a]
	return ok && spec.kinds[k]
}

// ValidAt reports whether the action is meaningful anywhere at a hierarchy
// level. Prefer ValidFor: this is the weaker check and exists only for callers
// that have a level and no kind.
func (a Action) ValidAt(l Level) bool {
	spec, ok := actionSpecs[a]
	if !ok {
		return false
	}
	for k := range spec.kinds {
		if kl, ok := LevelOf(k); ok && kl == l {
			return true
		}
	}
	return false
}

// ColumnScoped reports whether the action can be narrowed to specific columns.
// A column-level Deny on an action that is not column-scoped cannot be
// expressed by narrowing and must remove the grant entirely.
func (a Action) ColumnScoped() bool { return actionSpecs[a].columnScoped }

// Mutating reports whether the action can change data or structure.
func (a Action) Mutating() bool { return actionSpecs[a].mutating }

// ParseAction validates and returns an action.
func ParseAction(s string) (Action, error) {
	a := Action(s)
	if !a.Known() {
		return "", fmt.Errorf("unknown action %q", s)
	}
	return a, nil
}

// AllActions returns the vocabulary in stable order, for docs and validation.
func AllActions() []Action {
	out := make([]Action, 0, len(actionSpecs))
	for a := range actionSpecs {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ActionSet is a small, order-independent set of actions.
type ActionSet map[Action]struct{}

// NewActionSet builds a set.
func NewActionSet(actions ...Action) ActionSet {
	s := make(ActionSet, len(actions))
	for _, a := range actions {
		s[a] = struct{}{}
	}
	return s
}

// Has reports membership.
func (s ActionSet) Has(a Action) bool { _, ok := s[a]; return ok }

// Sorted returns members in stable order.
func (s ActionSet) Sorted() []Action {
	out := make([]Action, 0, len(s))
	for a := range s {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s ActionSet) String() string {
	parts := make([]string, 0, len(s))
	for _, a := range s.Sorted() {
		parts = append(parts, string(a))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

// BuiltinPermissionSets are the coarse, safe vocabulary most users should
// reach for. Raw actions remain available, but pgbedrock's experience is that
// unguided engine privileges are where people hurt themselves: the common case
// deserves a name, and the uncommon case deserves friction.
var BuiltinPermissionSets = map[string]ActionSet{
	"connect": NewActionSet(ActionConnect, ActionUsage),
	"reader":  NewActionSet(ActionConnect, ActionUsage, ActionSelect),
	"writer":  NewActionSet(ActionConnect, ActionUsage, ActionSelect, ActionInsert, ActionUpdate, ActionDelete),
	"ddl": NewActionSet(ActionConnect, ActionUsage, ActionSelect, ActionInsert, ActionUpdate,
		ActionDelete, ActionCreate, ActionAlter, ActionDrop, ActionTruncate, ActionReference, ActionTrigger),
	"executor": NewActionSet(ActionConnect, ActionUsage, ActionExecute),
}
