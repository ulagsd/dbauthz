package core

import (
	"reflect"
	"testing"
)

func TestParsePredicateRoundTrip(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"tenant_id = ${session.tenant}", "tenant_id = ${session.tenant}"},
		{"a = 1", "a = 1"},
		{"a <> 'x'", "a <> 'x'"},
		{"a != 'x'", "a <> 'x'"}, // != normalises to <>
		{"a >= 1.5", "a >= 1.5"},
		{"deleted IS NULL", "deleted IS NULL"},
		{"deleted IS NOT NULL", "deleted IS NOT NULL"},
		{"region IN ('eu', 'us')", "region IN ('eu', 'us')"},
		{"a = 1 AND b = 2", "a = 1 AND b = 2"},
		{"a = 1 OR b = 2", "a = 1 OR b = 2"},
		{"a = 1 AND b = 2 AND c = 3", "a = 1 AND b = 2 AND c = 3"},
		{"NOT (a = 1)", "NOT (a = 1)"},
		{"(a = 1 OR b = 2) AND c = 3", "(a = 1 OR b = 2) AND c = 3"},
		{"active = TRUE", "active = TRUE"},
		{"a = 'it''s'", "a = 'it''s'"},
		{"a = -5", "a = -5"},
		{"  a   =   1  ", "a = 1"},             // whitespace insensitive
		{"a = 1 and b = 2", "a = 1 AND b = 2"}, // keywords are case-insensitive
	} {
		p, err := ParsePredicate(tc.in)
		if err != nil {
			t.Errorf("ParsePredicate(%q): %v", tc.in, err)
			continue
		}
		if got := p.String(); got != tc.want {
			t.Errorf("ParsePredicate(%q).String() = %q, want %q", tc.in, got, tc.want)
		}
		// The canonical form must itself reparse to the same thing.
		again, err := ParsePredicate(p.String())
		if err != nil {
			t.Errorf("reparse %q: %v", p.String(), err)
			continue
		}
		if again.String() != p.String() {
			t.Errorf("reparse of %q is unstable: %q", p.String(), again.String())
		}
	}
}

func TestParsePredicateErrors(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"bare column", "a"},
		{"dangling operator", "a ="},
		{"unclosed paren", "(a = 1"},
		{"unterminated string", "a = 'x"},
		{"unterminated session ref", "a = ${session.tenant"},
		{"non-session interpolation", "a = ${env.HOME}"},
		{"empty session key", "a = ${session.}"},
		{"stray character", "a = 1 & b = 2"},
		{"trailing junk", "a = 1 b = 2"},
		{"IN without parens", "a IN 1"},
		{"IS without NULL", "a IS 1"},
		{"qualified column", "other.table.col = 1"},
	} {
		if p, err := ParsePredicate(tc.in); err == nil {
			t.Errorf("%s: ParsePredicate(%q) = %v, want error", tc.name, tc.in, p)
		}
	}
}

func TestPredicateStructure(t *testing.T) {
	p := MustParsePredicate("tenant_id = ${session.tenant} AND region IN ('eu', 'us')")
	and, ok := p.(*And)
	if !ok || len(and.Operands) != 2 {
		t.Fatalf("got %T with unexpected shape: %v", p, p)
	}
	first, ok := and.Operands[0].(*Comparison)
	if !ok {
		t.Fatalf("first operand is %T", and.Operands[0])
	}
	if !reflect.DeepEqual(first.Left, ColumnRef{Name: "tenant_id"}) {
		t.Errorf("left = %#v", first.Left)
	}
	if !reflect.DeepEqual(first.Right, SessionRef{Key: "tenant"}) {
		t.Errorf("right = %#v", first.Right)
	}
}

func TestIsDeferred(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"tenant_id = ${session.tenant}", true},
		{"a = 1", false},
		{"a = 1 AND b = ${session.role}", true},
		{"NOT (b = ${session.role})", true},
		{"region IN ('eu', ${session.home})", true},
		{"region IN ('eu', 'us')", false},
	} {
		if got := IsDeferred(MustParsePredicate(tc.in)); got != tc.want {
			t.Errorf("IsDeferred(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestReferencesAreDeduplicatedAndSorted(t *testing.T) {
	p := MustParsePredicate("a = ${session.tenant} AND b = ${session.tenant} AND c = ${session.actor}")
	want := []string{"actor", "tenant"}
	if got := p.References(); !reflect.DeepEqual(got, want) {
		t.Errorf("References() = %v, want %v", got, want)
	}
}

func TestColumns(t *testing.T) {
	p := MustParsePredicate("tenant_id = ${session.tenant} AND (region IN ('eu') OR owner IS NULL)")
	want := []string{"owner", "region", "tenant_id"}
	if got := Columns(p); !reflect.DeepEqual(got, want) {
		t.Errorf("Columns() = %v, want %v", got, want)
	}
}
