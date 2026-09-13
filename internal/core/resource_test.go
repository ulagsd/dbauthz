package core

import "testing"

func TestParseResourcePathRoundTrip(t *testing.T) {
	for _, s := range []string{
		"dbi:postgres:target/prod",
		"dbi:*:target/prod-*:db/app",
		"dbi:postgres:target/prod:db/app:schema/public:table/users",
		"dbi:postgres:target/prod:db/app:schema/public:table/users:column/ssn",
		"dbi:postgres:target/prod:db/app:schema/public:view/v_orders",
		// Identifiers containing the path syntax or glob metacharacters.
		"dbi:postgres:target/prod:db/app:schema/public:table/odd%3Aname",
		"dbi:postgres:target/prod:db/app:schema/public:table/lit%2Astar",
		"dbi:postgres:target/prod:db/app:schema/public:table/a%2Fb",
	} {
		p, err := ParseResourcePath(s)
		if err != nil {
			t.Fatalf("ParseResourcePath(%q): %v", s, err)
		}
		if got := p.String(); got != s {
			t.Errorf("round trip: got %q, want %q", got, s)
		}
	}
}

func TestParseResourcePathEscapedNamesAreLiteral(t *testing.T) {
	p := MustParseResourcePath("dbi:postgres:target/prod:db/app:schema/public:table/lit%2Astar")
	leaf, _ := p.Leaf()
	name, ok := leaf.Literal()
	if !ok || name != "lit*star" {
		t.Fatalf("leaf.Literal() = %q, %v; want %q, true", name, ok, "lit*star")
	}
	if p.HasGlob() {
		t.Error("an escaped '*' must not be treated as a wildcard")
	}
}

func TestParseResourcePathErrors(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"no prefix", "postgres:target/prod"},
		{"bad prefix", "xxx:postgres:target/prod"},
		{"too short", "dbi:postgres"},
		{"unknown kind", "dbi:postgres:target/prod:widget/x"},
		{"out of order", "dbi:postgres:target/prod:table/users:schema/public"},
		{"repeated level", "dbi:postgres:target/prod:db/a:db/b"},
		{"missing target", "dbi:postgres:db/app"},
		{"empty name", "dbi:postgres:target/"},
		{"empty engine", "dbi::target/prod"},
		{"no kv separator", "dbi:postgres:target"},
		{"bad escape", "dbi:postgres:target/a%ZZ"},
	} {
		if _, err := ParseResourcePath(tc.in); err == nil {
			t.Errorf("%s: ParseResourcePath(%q) succeeded, want error", tc.name, tc.in)
		}
	}
}

func TestMatches(t *testing.T) {
	concrete := MustParseResourcePath(
		"dbi:postgres:target/prod-eu:db/app:schema/public:table/orders")

	for _, tc := range []struct {
		pattern string
		want    bool
		why     string
	}{
		{"dbi:postgres:target/prod-eu:db/app:schema/public:table/orders", true, "exact"},
		{"dbi:*:target/prod-eu:db/app:schema/public:table/orders", true, "engine wildcard"},
		{"dbi:postgres:target/prod-*:db/app:schema/public:table/*", true, "segment wildcards"},
		{"dbi:postgres:target/prod-??:db/app:schema/public:table/orders", true, "single-char wildcard"},
		{"dbi:postgres:target/prod-eu:db/app", true, "prefix covers everything beneath"},
		{"dbi:postgres:target/prod-eu", true, "target prefix"},
		{"dbi:mysql:target/prod-eu:db/app:schema/public:table/orders", false, "engine mismatch"},
		{"dbi:postgres:target/prod-us:db/app:schema/public:table/orders", false, "target mismatch"},
		{"dbi:postgres:target/prod-eu:db/app:schema/public:view/orders", false, "kind mismatch at same level"},
		{"dbi:postgres:target/prod-eu:db/app:schema/private:table/orders", false, "schema mismatch"},
		{
			"dbi:postgres:target/prod-eu:db/app:schema/public:table/orders:column/total", false,
			"a column pattern must not match the whole table",
		},
	} {
		got := MustParseResourcePath(tc.pattern).Matches(concrete)
		if got != tc.want {
			t.Errorf("%s: %q.Matches(%q) = %v, want %v", tc.why, tc.pattern, concrete, got, tc.want)
		}
	}
}

func TestMatchesSkipsAbsentLevels(t *testing.T) {
	// A MySQL-shaped concrete path has no schema level at all. A pattern that
	// names a schema is more specific than the candidate and must not match.
	mysqlPath := MustParseResourcePath("dbi:mysql:target/prod:db/app:table/orders")

	if MustParseResourcePath("dbi:mysql:target/prod:db/app:schema/public:table/orders").Matches(mysqlPath) {
		t.Error("a schema-qualified pattern must not match a path with no schema level")
	}
	if !MustParseResourcePath("dbi:mysql:target/prod:db/app:table/*").Matches(mysqlPath) {
		t.Error("a schema-free pattern should match a MySQL path")
	}
}

func TestProject(t *testing.T) {
	p := MustParseResourcePath("dbi:*:target/prod:db/app:schema/public:table/orders")

	pg := p.Project("postgres", NewLevelSet(LevelTarget, LevelDatabase, LevelSchema, LevelObject, LevelAttribute))
	if got, want := pg.Path.String(), "dbi:postgres:target/prod:db/app:schema/public:table/orders"; got != want {
		t.Errorf("postgres projection = %q, want %q", got, want)
	}
	if len(pg.Dropped) != 0 {
		t.Errorf("postgres projection dropped %v, want nothing", pg.Dropped)
	}

	my := p.Project("mysql", NewLevelSet(LevelTarget, LevelDatabase, LevelObject, LevelAttribute))
	if got, want := my.Path.String(), "dbi:mysql:target/prod:db/app:table/orders"; got != want {
		t.Errorf("mysql projection = %q, want %q", got, want)
	}
	if len(my.Dropped) != 1 || my.Dropped[0].Kind != KindSchema {
		t.Fatalf("mysql projection dropped %v, want one schema segment", my.Dropped)
	}
	if !my.Lossy() {
		t.Error("dropping a concrete schema segment must be reported as lossy")
	}
}

func TestProjectWildcardDropIsNotLossy(t *testing.T) {
	p := MustParseResourcePath("dbi:*:target/prod:db/app:schema/*:table/orders")
	my := p.Project("mysql", NewLevelSet(LevelTarget, LevelDatabase, LevelObject, LevelAttribute))
	if len(my.Dropped) != 1 {
		t.Fatalf("dropped %v, want one segment", my.Dropped)
	}
	if my.Lossy() {
		t.Error("dropping schema/* constrains nothing and must not be lossy")
	}
}

func TestHasGlob(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"dbi:postgres:target/prod:db/app:schema/public:table/orders", false},
		{"dbi:*:target/prod:db/app:schema/public:table/orders", true},
		{"dbi:postgres:target/prod-*:db/app", true},
		{"dbi:postgres:target/prod:db/app:schema/public:table/order%3F", false},
	} {
		if got := MustParseResourcePath(tc.in).HasGlob(); got != tc.want {
			t.Errorf("%q.HasGlob() = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestDepthAndSegmentAt(t *testing.T) {
	p := MustParseResourcePath("dbi:postgres:target/prod:db/app:schema/public:table/users:column/ssn")
	if p.Depth() != LevelAttribute {
		t.Errorf("Depth() = %v, want %v", p.Depth(), LevelAttribute)
	}
	seg, ok := p.SegmentAt(LevelSchema)
	if !ok || seg.Pattern != "public" {
		t.Errorf("SegmentAt(schema) = %v, %v; want public", seg, ok)
	}
	if _, ok := MustParseResourcePath("dbi:postgres:target/prod").SegmentAt(LevelSchema); ok {
		t.Error("SegmentAt(schema) on a target-only path should report false")
	}
}

func TestMatchEncoded(t *testing.T) {
	for _, tc := range []struct {
		pattern, name string
		want          bool
	}{
		{"", "", true},
		{"", "a", false},
		{"*", "", true},
		{"*", "anything", true},
		{"a*", "abc", true},
		{"*c", "abc", true},
		{"a*c", "abc", true},
		{"a*c", "ac", true},
		{"a*c", "abd", false},
		{"?", "a", true},
		{"?", "ab", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"**", "ab", true},
		{"a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaab", true},  // backtracking, not exponential
		{"a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaac", false}, // the pathological miss
		{"prod-*", "prod-eu", true},
		{"prod-*", "staging-eu", false},
		// Encoded literals decode before matching.
		{"lit%2Astar", "lit%2Astar", true}, // literal star matches literal star
		{"lit*star", "lit%2Astar", true},   // wildcard also covers it
		{"lit%2Astar", "litXstar", false},  // literal star does not match any char
		{"a?c", "a%2Ac", true},             // '?' matches one decoded character
	} {
		if got := matchEncoded(tc.pattern, tc.name); got != tc.want {
			t.Errorf("matchEncoded(%q, %q) = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

func TestLiteralSegmentRoundTrip(t *testing.T) {
	for _, name := range []string{"plain", "a:b", "a/b", "a*b", "a?b", "100%", "%:/*?", "Ünïcode"} {
		seg := LiteralSegment(KindTable, name)
		if seg.HasGlob() {
			t.Errorf("LiteralSegment(%q) must never be a glob, got pattern %q", name, seg.Pattern)
		}
		got, ok := seg.Literal()
		if !ok || got != name {
			t.Errorf("LiteralSegment(%q).Literal() = %q, %v", name, got, ok)
		}
	}
}

// A name read from a live catalog must never be reinterpreted as a wildcard.
func TestLiteralSegmentDefeatsInjection(t *testing.T) {
	evil := LiteralSegment(KindTable, "*")
	pattern := Segment{Kind: KindTable, Pattern: "*"}
	if !matchEncoded(pattern.Pattern, evil.Pattern) {
		t.Error("wildcard pattern should match a literally-named table")
	}
	if matchEncoded(evil.Pattern, "orders") {
		t.Error("a table literally named \"*\" must not match every other table")
	}
}
