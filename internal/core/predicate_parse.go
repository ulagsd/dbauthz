package core

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// ParsePredicate parses the row-filter expression grammar:
//
//	expr       := orExpr
//	orExpr     := andExpr ( "OR" andExpr )*
//	andExpr    := notExpr ( "AND" notExpr )*
//	notExpr    := "NOT" notExpr | primary
//	primary    := "(" expr ")" | comparison
//	comparison := operand ( cmpOp operand
//	                      | "IN" "(" operand ( "," operand )* ")"
//	                      | "IS" [ "NOT" ] "NULL" )
//	operand    := identifier | literal | "${session." identifier "}"
//
// Recursive descent with one token of lookahead. The grammar is small on
// purpose; see the Predicate doc comment for why it must stay that way.
func ParsePredicate(s string) (Predicate, error) {
	toks, err := lexPredicate(s)
	if err != nil {
		return nil, err
	}
	p := &predParser{toks: toks, src: s}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if !p.at(tokEOF) {
		return nil, p.errf("unexpected %s after expression", p.peek().describe())
	}
	return expr, nil
}

// MustParsePredicate is ParsePredicate for fixtures and constants.
func MustParsePredicate(s string) Predicate {
	p, err := ParsePredicate(s)
	if err != nil {
		panic(err)
	}
	return p
}

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokNumber
	tokString
	tokSession
	tokOp     // = <> != < <= > >=
	tokLParen // (
	tokRParen // )
	tokComma
	tokKeyword // AND OR NOT IN IS NULL TRUE FALSE
)

type token struct {
	kind tokKind
	text string
	pos  int
}

func (t token) describe() string {
	if t.kind == tokEOF {
		return "end of expression"
	}
	return strconv.Quote(t.text)
}

var keywords = map[string]bool{
	"AND": true, "OR": true, "NOT": true, "IN": true,
	"IS": true, "NULL": true, "TRUE": true, "FALSE": true,
}

func lexPredicate(s string) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++

		case c == '(':
			out = append(out, token{tokLParen, "(", i})
			i++
		case c == ')':
			out = append(out, token{tokRParen, ")", i})
			i++
		case c == ',':
			out = append(out, token{tokComma, ",", i})
			i++

		case c == '=':
			out = append(out, token{tokOp, "=", i})
			i++
		case c == '<':
			switch {
			case strings.HasPrefix(s[i:], "<>"):
				out = append(out, token{tokOp, "<>", i})
				i += 2
			case strings.HasPrefix(s[i:], "<="):
				out = append(out, token{tokOp, "<=", i})
				i += 2
			default:
				out = append(out, token{tokOp, "<", i})
				i++
			}
		case c == '>':
			if strings.HasPrefix(s[i:], ">=") {
				out = append(out, token{tokOp, ">=", i})
				i += 2
			} else {
				out = append(out, token{tokOp, ">", i})
				i++
			}
		case c == '!':
			if !strings.HasPrefix(s[i:], "!=") {
				return nil, fmt.Errorf("predicate %q: stray %q at %d", s, "!", i)
			}
			out = append(out, token{tokOp, "<>", i})
			i += 2

		case c == '\'':
			j := i + 1
			var b strings.Builder
			for {
				if j >= len(s) {
					return nil, fmt.Errorf("predicate %q: unterminated string at %d", s, i)
				}
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' { // '' is an escaped quote
						b.WriteByte('\'')
						j += 2
						continue
					}
					break
				}
				b.WriteByte(s[j])
				j++
			}
			out = append(out, token{tokString, b.String(), i})
			i = j + 1

		case strings.HasPrefix(s[i:], "${"):
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return nil, fmt.Errorf("predicate %q: unterminated ${...} at %d", s, i)
			}
			inner := s[i+2 : i+end]
			key, ok := strings.CutPrefix(inner, "session.")
			if !ok || key == "" {
				return nil, fmt.Errorf("predicate %q: %q is not a session reference; "+
					"the only supported form is ${session.<name>}", s, "${"+inner+"}")
			}
			if !isIdent(key) {
				return nil, fmt.Errorf("predicate %q: invalid session key %q", s, key)
			}
			out = append(out, token{tokSession, key, i})
			i += end + 1

		case c >= '0' && c <= '9' || c == '-' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
			j := i + 1
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == '.') {
				j++
			}
			out = append(out, token{tokNumber, s[i:j], i})
			i = j

		case isIdentStart(rune(c)):
			j := i
			for j < len(s) && isIdentPart(rune(s[j])) {
				j++
			}
			word := s[i:j]
			kind := tokIdent
			if keywords[strings.ToUpper(word)] {
				kind, word = tokKeyword, strings.ToUpper(word)
			}
			out = append(out, token{kind, word, i})
			i = j

		default:
			return nil, fmt.Errorf("predicate %q: unexpected character %q at %d", s, string(c), i)
		}
	}
	return append(out, token{tokEOF, "", len(s)}), nil
}

func isIdentStart(r rune) bool {
	return r == '_' || unicode.IsLetter(r)
}
func isIdentPart(r rune) bool {
	return r == '_' || r == '$' || unicode.IsLetter(r) || unicode.IsDigit(r)
}
func isIdent(s string) bool {
	if s == "" || !isIdentStart(rune(s[0])) {
		return false
	}
	for _, r := range s[1:] {
		if !isIdentPart(r) {
			return false
		}
	}
	return true
}

type predParser struct {
	toks []token
	pos  int
	src  string
}

func (p *predParser) peek() token { return p.toks[p.pos] }
func (p *predParser) next() token { t := p.toks[p.pos]; p.pos++; return t }

func (p *predParser) at(k tokKind) bool { return p.peek().kind == k }

func (p *predParser) atKeyword(kw string) bool {
	t := p.peek()
	return t.kind == tokKeyword && t.text == kw
}

func (p *predParser) acceptKeyword(kw string) bool {
	if p.atKeyword(kw) {
		p.pos++
		return true
	}
	return false
}

func (p *predParser) errf(format string, args ...any) error {
	return fmt.Errorf("predicate %q at offset %d: %s", p.src, p.peek().pos, fmt.Sprintf(format, args...))
}

func (p *predParser) parseOr() (Predicate, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	if !p.atKeyword("OR") {
		return left, nil
	}
	ops := []Predicate{left}
	for p.acceptKeyword("OR") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		ops = append(ops, right)
	}
	return &Or{Operands: ops}, nil
}

func (p *predParser) parseAnd() (Predicate, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	if !p.atKeyword("AND") {
		return left, nil
	}
	ops := []Predicate{left}
	for p.acceptKeyword("AND") {
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		ops = append(ops, right)
	}
	return &And{Operands: ops}, nil
}

func (p *predParser) parseNot() (Predicate, error) {
	if p.acceptKeyword("NOT") {
		inner, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &Not{Operand: inner}, nil
	}
	return p.parsePrimary()
}

func (p *predParser) parsePrimary() (Predicate, error) {
	if p.at(tokLParen) {
		p.next()
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if !p.at(tokRParen) {
			return nil, p.errf("want ')', got %s", p.peek().describe())
		}
		p.next()
		return inner, nil
	}
	return p.parseComparison()
}

func (p *predParser) parseComparison() (Predicate, error) {
	left, err := p.parseOperand()
	if err != nil {
		return nil, err
	}

	switch {
	case p.at(tokOp):
		op := CmpOp(p.next().text)
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return &Comparison{Op: op, Left: left, Right: right}, nil

	case p.acceptKeyword("IN"):
		if !p.at(tokLParen) {
			return nil, p.errf("want '(' after IN, got %s", p.peek().describe())
		}
		p.next()
		var list []Operand
		for {
			o, err := p.parseOperand()
			if err != nil {
				return nil, err
			}
			list = append(list, o)
			if p.at(tokComma) {
				p.next()
				continue
			}
			break
		}
		if !p.at(tokRParen) {
			return nil, p.errf("want ')' to close IN list, got %s", p.peek().describe())
		}
		p.next()
		return &Comparison{Op: OpIn, Left: left, List: list}, nil

	case p.acceptKeyword("IS"):
		negated := p.acceptKeyword("NOT")
		if !p.acceptKeyword("NULL") {
			return nil, p.errf("want NULL after IS, got %s", p.peek().describe())
		}
		op := OpIsNull
		if negated {
			op = OpIsNotNull
		}
		return &Comparison{Op: op, Left: left}, nil
	}

	return nil, p.errf("want a comparison operator after %s, got %s", left, p.peek().describe())
}

func (p *predParser) parseOperand() (Operand, error) {
	t := p.next()
	switch t.kind {
	case tokIdent:
		return ColumnRef{Name: t.text}, nil
	case tokSession:
		return SessionRef{Key: t.text}, nil
	case tokString:
		return Literal{Value: t.text}, nil
	case tokNumber:
		if i, err := strconv.ParseInt(t.text, 10, 64); err == nil {
			return Literal{Value: i}, nil
		}
		f, err := strconv.ParseFloat(t.text, 64)
		if err != nil {
			return nil, fmt.Errorf("predicate %q: bad number %q at %d", p.src, t.text, t.pos)
		}
		return Literal{Value: f}, nil
	case tokKeyword:
		switch t.text {
		case "TRUE":
			return Literal{Value: true}, nil
		case "FALSE":
			return Literal{Value: false}, nil
		case "NULL":
			return Literal{Value: nil}, nil
		}
	}
	p.pos-- // report the offending token, not the one after it
	return nil, p.errf("want a column, literal or ${session.*} reference, got %s", t.describe())
}
