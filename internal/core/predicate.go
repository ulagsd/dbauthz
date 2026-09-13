package core

import (
	"fmt"
	"sort"
	"strings"
)

// Predicate is an engine-neutral boolean expression used for row filters.
//
// The grammar is kept deliberately tiny — comparisons, boolean operators,
// column references, literals and session references. It is not a query
// language and must never grow into one: every construct added here has to be
// renderable by every provider, and the moment it cannot be, one policy stops
// meaning the same thing on two engines.
//
// Anything beyond this expressiveness belongs in a database view that the
// policy then references, not in the policy itself.
type Predicate interface {
	predicate()
	// References returns the session keys the predicate depends on. A
	// predicate with no session references is static and can be evaluated when
	// the plan is built; one with references is deferred and must be lowered
	// into an engine-native runtime construct, or refused.
	References() []string
	String() string
}

// CmpOp is a comparison operator.
type CmpOp string

// The supported comparison operators.
const (
	OpEq        CmpOp = "="
	OpNe        CmpOp = "<>"
	OpLt        CmpOp = "<"
	OpLte       CmpOp = "<="
	OpGt        CmpOp = ">"
	OpGte       CmpOp = ">="
	OpIn        CmpOp = "IN"
	OpIsNull    CmpOp = "IS NULL"
	OpIsNotNull CmpOp = "IS NOT NULL"
)

// Operand is a comparison operand.
type Operand interface {
	operand()
	String() string
}

// ColumnRef names a column of the table the filter is attached to.
// Qualified names are not permitted: a row filter that reaches into another
// table is not portable, and on several engines not expressible at all.
type ColumnRef struct{ Name string }

// Literal is a constant. Value is a string, int64, float64, bool, or nil.
type Literal struct{ Value any }

// SessionRef is a value supplied by the database session at query time, such
// as the connected principal or a tenant set by the application. This is what
// makes a predicate deferred, and what each provider renders differently:
// current_setting() on PostgreSQL, a context function on Snowflake, and
// nothing at all on MySQL — where it becomes ErrUnsupported.
type SessionRef struct{ Key string }

func (ColumnRef) operand()  {}
func (Literal) operand()    {}
func (SessionRef) operand() {}

func (c ColumnRef) String() string  { return c.Name }
func (s SessionRef) String() string { return "${session." + s.Key + "}" }
func (l Literal) String() string {
	switch v := l.Value.(type) {
	case nil:
		return "NULL"
	case string:
		return "'" + strings.ReplaceAll(v, "'", "''") + "'"
	case bool:
		if v {
			return "TRUE"
		}
		return "FALSE"
	default:
		return fmt.Sprint(v)
	}
}

// Comparison compares an operand against another, or against a list for IN.
// Right is nil for the unary null tests.
type Comparison struct {
	Op    CmpOp
	Left  Operand
	Right Operand
	List  []Operand // populated only for OpIn
}

// And is a conjunction of two or more predicates.
type And struct{ Operands []Predicate }

// Or is a disjunction of two or more predicates.
type Or struct{ Operands []Predicate }

// Not negates a predicate.
type Not struct{ Operand Predicate }

func (*Comparison) predicate() {}
func (*And) predicate()        {}
func (*Or) predicate()         {}
func (*Not) predicate()        {}

// References returns the session keys this comparison depends on.
func (c *Comparison) References() []string {
	var out []string
	if s, ok := c.Left.(SessionRef); ok {
		out = append(out, s.Key)
	}
	if s, ok := c.Right.(SessionRef); ok {
		out = append(out, s.Key)
	}
	for _, o := range c.List {
		if s, ok := o.(SessionRef); ok {
			out = append(out, s.Key)
		}
	}
	return out
}

// References returns the session keys any operand depends on.
func (a *And) References() []string { return childRefs(a.Operands) }

// References returns the session keys any operand depends on.
func (o *Or) References() []string { return childRefs(o.Operands) }

// References returns the session keys the negated predicate depends on.
func (n *Not) References() []string { return n.Operand.References() }

func childRefs(ps []Predicate) []string {
	seen := map[string]struct{}{}
	for _, p := range ps {
		for _, r := range p.References() {
			seen[r] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func (c *Comparison) String() string {
	switch c.Op {
	case OpIsNull, OpIsNotNull:
		return c.Left.String() + " " + string(c.Op)
	case OpIn:
		parts := make([]string, len(c.List))
		for i, o := range c.List {
			parts[i] = o.String()
		}
		return c.Left.String() + " IN (" + strings.Join(parts, ", ") + ")"
	default:
		return c.Left.String() + " " + string(c.Op) + " " + c.Right.String()
	}
}

func (a *And) String() string { return joinPreds(a.Operands, " AND ") }
func (o *Or) String() string  { return joinPreds(o.Operands, " OR ") }
func (n *Not) String() string { return "NOT (" + n.Operand.String() + ")" }

func joinPreds(ps []Predicate, sep string) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		if _, isCmp := p.(*Comparison); isCmp {
			parts[i] = p.String()
		} else {
			parts[i] = "(" + p.String() + ")"
		}
	}
	return strings.Join(parts, sep)
}

// IsDeferred reports whether the predicate depends on session state and so
// must be lowered into an engine-native runtime construct rather than
// evaluated when the plan is built.
func IsDeferred(p Predicate) bool { return len(p.References()) > 0 }

// Columns returns the column names a predicate reads, in stable order. A
// provider needs these to check the columns exist and are readable before it
// emits a row policy that would otherwise fail at query time.
func Columns(p Predicate) []string {
	seen := map[string]struct{}{}
	collectColumns(p, seen)
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func collectColumns(p Predicate, seen map[string]struct{}) {
	switch v := p.(type) {
	case *Comparison:
		for _, o := range append([]Operand{v.Left, v.Right}, v.List...) {
			if c, ok := o.(ColumnRef); ok {
				seen[c.Name] = struct{}{}
			}
		}
	case *And:
		for _, c := range v.Operands {
			collectColumns(c, seen)
		}
	case *Or:
		for _, c := range v.Operands {
			collectColumns(c, seen)
		}
	case *Not:
		collectColumns(v.Operand, seen)
	}
}
