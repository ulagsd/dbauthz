// Package core holds db-iam's engine-neutral domain types.
//
// Nothing in this package may import a database driver or reference a
// specific engine. It is the vocabulary shared by the policy layer, the
// solver, and every provider. Providers project these types onto their
// engine's own model; the reverse never happens.
package core

import (
	"fmt"
	"strings"
)

// Level is a position in the canonical resource hierarchy. Engines differ in
// which levels they have: PostgreSQL uses every level, MySQL has no schema
// level (its "database" is the schema), MongoDB has no attribute grants at all.
//
// Modelling levels rather than a flat segment list is what lets one policy
// target every engine: a path is portable, and Project drops the levels a
// given provider does not implement.
type Level int

// The canonical hierarchy levels, from the instance down to a single column.
const (
	LevelTarget    Level = iota // the database instance itself
	LevelDatabase               // postgres: database, mysql: schema
	LevelSchema                 // postgres/snowflake only
	LevelObject                 // table, view, sequence, function, collection
	LevelAttribute              // column, field
)

func (l Level) String() string {
	switch l {
	case LevelTarget:
		return "target"
	case LevelDatabase:
		return "database"
	case LevelSchema:
		return "schema"
	case LevelObject:
		return "object"
	case LevelAttribute:
		return "attribute"
	}
	return fmt.Sprintf("level(%d)", int(l))
}

// SegmentKind is the concrete noun used in a path. Several kinds may share a
// Level: a table, a view and a sequence are all LevelObject.
type SegmentKind string

// The recognised segment kinds. Several may share a Level.
const (
	KindTarget     SegmentKind = "target"
	KindDatabase   SegmentKind = "db"
	KindSchema     SegmentKind = "schema"
	KindTable      SegmentKind = "table"
	KindView       SegmentKind = "view"
	KindSequence   SegmentKind = "sequence"
	KindFunction   SegmentKind = "function"
	KindProcedure  SegmentKind = "procedure"
	KindCollection SegmentKind = "collection"
	KindColumn     SegmentKind = "column"
	KindField      SegmentKind = "field"
)

var kindLevels = map[SegmentKind]Level{
	KindTarget:     LevelTarget,
	KindDatabase:   LevelDatabase,
	KindSchema:     LevelSchema,
	KindTable:      LevelObject,
	KindView:       LevelObject,
	KindSequence:   LevelObject,
	KindFunction:   LevelObject,
	KindProcedure:  LevelObject,
	KindCollection: LevelObject,
	KindColumn:     LevelAttribute,
	KindField:      LevelAttribute,
}

// LevelOf reports the hierarchy level of a kind, and whether the kind is known.
func LevelOf(k SegmentKind) (Level, bool) {
	l, ok := kindLevels[k]
	return l, ok
}

// AnyEngine is the engine wildcard: the path applies to every target whose
// capability profile can express it.
const AnyEngine = "*"

// Segment is one kind/name pair.
//
// Pattern holds the name in path-encoded form: a bare '*' matches any run of
// characters and a bare '?' matches exactly one, while any character may be
// written %XX to make it literal. Storing the encoded form is what lets a
// table genuinely named "report*" coexist with wildcard patterns; a decoded
// name could not tell the two apart.
//
// Build segments from live catalog data with LiteralSegment, never by
// assigning Pattern directly.
type Segment struct {
	Kind    SegmentKind
	Pattern string
}

// LiteralSegment builds a segment whose name is entirely literal, encoding any
// metacharacters it contains.
func LiteralSegment(kind SegmentKind, name string) Segment {
	return Segment{Kind: kind, Pattern: escapeLiteral(name)}
}

// Level reports the segment's hierarchy level. Unknown kinds report false.
func (s Segment) Level() (Level, bool) { return LevelOf(s.Kind) }

// HasGlob reports whether the segment contains an unescaped metacharacter.
func (s Segment) HasGlob() bool { return hasMeta(s.Pattern) }

// Literal returns the decoded name, and false if the segment is a wildcard
// pattern and so names no single object.
func (s Segment) Literal() (string, bool) { return decodeLiteral(s.Pattern) }

// String renders the segment in canonical form.
func (s Segment) String() string { return string(s.Kind) + "/" + s.Pattern }

// ResourcePath identifies a database object, or a set of them.
//
// Canonical form:
//
//	dbi:<engine>:target/<t>:db/<d>[:schema/<s>]:table/<tbl>[:column/<c>]
//
// Segments are ordered by strictly increasing Level. Every segment names its
// kind explicitly — there is no bare wildcard segment — because kind is what
// makes projection onto a different engine's hierarchy well defined.
type ResourcePath struct {
	Engine   string // concrete engine id, or AnyEngine
	Segments []Segment
}

const pathPrefix = "dbi"

// validEngine accepts AnyEngine or a plain engine id. Engine ids are a closed
// set of lowercase identifiers, so unlike object names they need no encoding.
func validEngine(e string) error {
	if e == AnyEngine {
		return nil
	}
	if e == "" {
		return fmt.Errorf("empty (use %q for any)", AnyEngine)
	}
	for i := 0; i < len(e); i++ {
		c := e[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !ok {
			return fmt.Errorf("%q is not a valid engine id", e)
		}
	}
	return nil
}

// ParseResourcePath parses the canonical string form.
func ParseResourcePath(s string) (ResourcePath, error) {
	var p ResourcePath

	parts := splitUnescaped(s, ':')
	if len(parts) < 3 {
		return p, fmt.Errorf("resource path %q: want the form %s:<engine>:<kind>/<name>", s, pathPrefix)
	}
	if parts[0] != pathPrefix {
		return p, fmt.Errorf("resource path %q: must begin with %q", s, pathPrefix)
	}

	if err := validEngine(parts[1]); err != nil {
		return p, fmt.Errorf("resource path %q: engine: %w", s, err)
	}
	p.Engine = parts[1]

	prev := Level(-1)
	for _, raw := range parts[2:] {
		kv := splitUnescaped(raw, '/')
		if len(kv) != 2 {
			return p, fmt.Errorf("resource path %q: segment %q: want <kind>/<name>", s, raw)
		}
		kind := SegmentKind(kv[0])
		level, ok := LevelOf(kind)
		if !ok {
			return p, fmt.Errorf("resource path %q: unknown segment kind %q", s, kv[0])
		}
		if level <= prev {
			return p, fmt.Errorf("resource path %q: segment %q is out of hierarchy order", s, raw)
		}
		prev = level

		if kv[1] == "" {
			return p, fmt.Errorf("resource path %q: segment %q has an empty name", s, raw)
		}
		if _, err := compilePattern(kv[1]); err != nil {
			return p, fmt.Errorf("resource path %q: segment %q: %w", s, raw, err)
		}
		p.Segments = append(p.Segments, Segment{Kind: kind, Pattern: kv[1]})
	}

	if len(p.Segments) == 0 {
		return p, fmt.Errorf("resource path %q: no segments", s)
	}
	if p.Segments[0].Kind != KindTarget {
		return p, fmt.Errorf("resource path %q: must begin at %s/", s, KindTarget)
	}
	return p, nil
}

// MustParseResourcePath is ParseResourcePath for test fixtures and constants.
func MustParseResourcePath(s string) ResourcePath {
	p, err := ParseResourcePath(s)
	if err != nil {
		panic(err)
	}
	return p
}

// String renders the canonical form. Parse(String(p)) == p for any valid p.
func (p ResourcePath) String() string {
	var b strings.Builder
	b.WriteString(pathPrefix)
	b.WriteByte(':')
	b.WriteString(p.Engine)
	for _, seg := range p.Segments {
		b.WriteByte(':')
		b.WriteString(seg.String())
	}
	return b.String()
}

// Depth is the level of the most specific segment.
func (p ResourcePath) Depth() Level {
	if len(p.Segments) == 0 {
		return LevelTarget
	}
	l, _ := p.Segments[len(p.Segments)-1].Level()
	return l
}

// Leaf returns the most specific segment.
func (p ResourcePath) Leaf() (Segment, bool) {
	if len(p.Segments) == 0 {
		return Segment{}, false
	}
	return p.Segments[len(p.Segments)-1], true
}

// HasGlob reports whether any segment, or the engine, is a wildcard.
// A path with no globs is concrete: it names at most one object.
func (p ResourcePath) HasGlob() bool {
	if p.Engine == AnyEngine {
		return true
	}
	for _, s := range p.Segments {
		if s.HasGlob() {
			return true
		}
	}
	return false
}

// SegmentAt returns the segment at the given level, if the path has one.
func (p ResourcePath) SegmentAt(l Level) (Segment, bool) {
	for _, s := range p.Segments {
		if sl, ok := s.Level(); ok && sl == l {
			return s, true
		}
	}
	return Segment{}, false
}

// Matches reports whether p, read as a pattern, selects the concrete path c.
//
// Matching is level-wise, and a pattern that stops short of c's depth matches
// c and everything beneath it: db/app matches every table in that database.
// The reverse does not hold — a pattern deeper than c never matches, because
// a policy about a column says nothing about the whole table.
func (p ResourcePath) Matches(c ResourcePath) bool {
	if p.Engine != AnyEngine && p.Engine != c.Engine {
		return false
	}
	for _, ps := range p.Segments {
		pl, ok := ps.Level()
		if !ok {
			return false
		}
		cs, ok := c.SegmentAt(pl)
		if !ok {
			return false // pattern is more specific than the candidate
		}
		// Kinds at the same level must agree when both are concrete nouns,
		// so table/x never matches view/x.
		if ps.Kind != cs.Kind {
			return false
		}
		if !matchEncoded(ps.Pattern, cs.Pattern) {
			return false
		}
	}
	return true
}

// Projection is the result of mapping a path onto one engine's hierarchy.
// Dropped records the segments the engine has no level for, so the planner can
// tell the operator that "schema/public" was discarded on MySQL rather than
// silently widening the policy.
type Projection struct {
	Path    ResourcePath
	Dropped []Segment
}

// Lossy reports whether projection discarded a segment that constrained the
// path. A dropped wildcard segment constrains nothing and is not lossy.
func (pr Projection) Lossy() bool {
	for _, s := range pr.Dropped {
		if s.Pattern != "*" {
			return true
		}
	}
	return false
}

// Project maps p onto the levels an engine actually implements, as declared by
// its capability profile. Segments at unsupported levels are dropped.
//
// This is how one portable policy reaches engines with different hierarchy
// depths: dbi:*:target/t:db/app:schema/public:table/orders projects onto MySQL
// as target/t:db/app:table/orders, with schema/public reported as dropped.
func (p ResourcePath) Project(engine string, levels LevelSet) Projection {
	out := ResourcePath{Engine: engine}
	pr := Projection{}
	for _, s := range p.Segments {
		l, ok := s.Level()
		if !ok || !levels.Has(l) {
			pr.Dropped = append(pr.Dropped, s)
			continue
		}
		out.Segments = append(out.Segments, s)
	}
	pr.Path = out
	return pr
}

// LevelSet is the set of hierarchy levels an engine implements.
type LevelSet uint8

// NewLevelSet builds a LevelSet from levels.
func NewLevelSet(levels ...Level) LevelSet {
	var s LevelSet
	for _, l := range levels {
		s |= 1 << uint(l)
	}
	return s
}

// Has reports membership.
func (s LevelSet) Has(l Level) bool { return s&(1<<uint(l)) != 0 }

// Levels lists members in hierarchy order.
func (s LevelSet) Levels() []Level {
	var out []Level
	for l := LevelTarget; l <= LevelAttribute; l++ {
		if s.Has(l) {
			out = append(out, l)
		}
	}
	return out
}

func (s LevelSet) String() string {
	parts := make([]string, 0, 5)
	for _, l := range s.Levels() {
		parts = append(parts, l.String())
	}
	return "{" + strings.Join(parts, ",") + "}"
}
