package core

import "testing"

func TestActionValidForKind(t *testing.T) {
	for _, tc := range []struct {
		action Action
		kind   SegmentKind
		want   bool
		why    string
	}{
		{ActionSelect, KindTable, true, "select on a table"},
		{ActionSelect, KindView, true, "select on a view"},
		{ActionSelect, KindColumn, true, "select narrowed to a column"},
		{ActionSelect, KindSchema, false, "select is not a schema privilege"},
		// The distinction a level-only check would lose: both are LevelObject.
		{ActionUsage, KindSequence, true, "usage on a sequence"},
		{ActionUsage, KindTable, false, "usage is meaningless on a table"},
		{ActionUsage, KindSchema, true, "usage on a schema"},
		{ActionExecute, KindFunction, true, "execute on a function"},
		{ActionExecute, KindTable, false, "execute is meaningless on a table"},
		{ActionTruncate, KindTable, true, "truncate on a table"},
		{ActionTruncate, KindView, false, "a view cannot be truncated"},
		{ActionConnect, KindDatabase, true, "connect to a database"},
		{ActionConnect, KindTable, false, "connect is not an object privilege"},
		{ActionCreate, KindSchema, true, "create within a schema"},
		{ActionTemporary, KindDatabase, true, "temp tables are a database privilege"},
	} {
		if got := tc.action.ValidFor(tc.kind); got != tc.want {
			t.Errorf("%s: %s.ValidFor(%s) = %v, want %v", tc.why, tc.action, tc.kind, got, tc.want)
		}
	}
}

func TestActionColumnScoped(t *testing.T) {
	// Exactly these four accept a column list on every engine with column
	// grants. Anything else narrowed to columns is a policy error.
	scoped := NewActionSet(ActionSelect, ActionInsert, ActionUpdate, ActionReference)
	for _, a := range AllActions() {
		if got, want := a.ColumnScoped(), scoped.Has(a); got != want {
			t.Errorf("%s.ColumnScoped() = %v, want %v", a, got, want)
		}
	}
}

func TestActionMutating(t *testing.T) {
	for _, a := range []Action{ActionSelect, ActionConnect, ActionUsage, ActionExecute} {
		if a.Mutating() {
			t.Errorf("%s should not be classified as mutating", a)
		}
	}
	for _, a := range []Action{ActionInsert, ActionUpdate, ActionDelete, ActionTruncate, ActionDrop, ActionAlter} {
		if !a.Mutating() {
			t.Errorf("%s should be classified as mutating", a)
		}
	}
}

func TestParseAction(t *testing.T) {
	if _, err := ParseAction("db:Select"); err != nil {
		t.Errorf("ParseAction(db:Select): %v", err)
	}
	for _, bad := range []string{"", "Select", "db:select", "db:Nope", "s3:GetObject"} {
		if _, err := ParseAction(bad); err == nil {
			t.Errorf("ParseAction(%q) succeeded, want error", bad)
		}
	}
}

// Every action must be attachable somewhere, or it is dead vocabulary that a
// policy could name and nothing could ever satisfy.
func TestEveryActionIsAttachable(t *testing.T) {
	for _, a := range AllActions() {
		spec := actionSpecs[a]
		if len(spec.kinds) == 0 {
			t.Errorf("%s applies to no object kind", a)
		}
		for k := range spec.kinds {
			if _, ok := LevelOf(k); !ok {
				t.Errorf("%s references unknown kind %q", a, k)
			}
		}
	}
}

func TestBuiltinPermissionSetsUseKnownActions(t *testing.T) {
	for name, set := range BuiltinPermissionSets {
		for _, a := range set.Sorted() {
			if !a.Known() {
				t.Errorf("permission set %q contains unknown action %q", name, a)
			}
		}
	}
	// The coarse vocabulary should be ordered by strength, since that is the
	// property users assume when picking one.
	reader, writer := BuiltinPermissionSets["reader"], BuiltinPermissionSets["writer"]
	for _, a := range reader.Sorted() {
		if !writer.Has(a) {
			t.Errorf("writer should include everything reader has, missing %q", a)
		}
	}
	if writer.Has(ActionDrop) {
		t.Error("writer must not include DDL privileges")
	}
}

func TestColumnSetRemoveExpressesDenyByNarrowing(t *testing.T) {
	available := []string{"id", "email", "name", "ssn"}

	// The whole point: no engine has a deny, so a column-level deny becomes a
	// narrower grant rather than a removed one.
	got := AllColumns().Remove(available, "ssn")
	want := []string{"email", "id", "name"}
	if len(got.Name) != len(want) {
		t.Fatalf("Remove() = %v, want %v", got.Name, want)
	}
	for i := range want {
		if got.Name[i] != want[i] {
			t.Fatalf("Remove() = %v, want %v", got.Name, want)
		}
	}
	if got.All {
		t.Error("narrowing must materialise All into an explicit list")
	}
}

func TestColumnSetIntersect(t *testing.T) {
	a := NamedColumns("id", "email", "name")
	b := NamedColumns("email", "name", "ssn")
	got := a.Intersect(b)
	if len(got.Name) != 2 || got.Name[0] != "email" || got.Name[1] != "name" {
		t.Errorf("Intersect = %v, want [email name]", got.Name)
	}
	if all := AllColumns().Intersect(b); all != b {
		t.Error("intersecting All with a set should yield the set")
	}
}

func TestColumnSetEmptyMeansDropTheGrant(t *testing.T) {
	if !NamedColumns().Empty() {
		t.Error("a set with no columns must report Empty")
	}
	if AllColumns().Empty() {
		t.Error("All is never empty")
	}
	// Denying every column leaves nothing to grant.
	if !AllColumns().Remove([]string{"a"}, "a").Empty() {
		t.Error("removing every available column should yield an empty set")
	}
}
