package core

import (
	"fmt"
	"strings"
)

// Segment names are stored path-encoded, because a decoded name cannot
// distinguish a wildcard from a table genuinely called "report*". In encoded
// form '*' and '?' are always metacharacters and a literal one is written
// %2A / %3F. Characters that collide with the path syntax are encoded too.
const mustEscape = `%:/*?`

// escapeLiteral encodes a name so that every character in it is literal.
// Values read from a live catalog must go through this.
func escapeLiteral(s string) string {
	if !strings.ContainsAny(s, mustEscape) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		if c := s[i]; strings.IndexByte(mustEscape, c) >= 0 {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// patToken is one unit of a compiled segment pattern.
type patToken struct {
	meta byte // '*', '?', or 0 for a literal
	ch   byte // the literal byte, when meta == 0
}

// compilePattern decodes an encoded segment name into tokens, resolving %XX
// escapes to literals and leaving bare '*' and '?' as metacharacters.
func compilePattern(encoded string) ([]patToken, error) {
	out := make([]patToken, 0, len(encoded))
	for i := 0; i < len(encoded); i++ {
		switch c := encoded[i]; c {
		case '*', '?':
			out = append(out, patToken{meta: c})
		case '%':
			if i+2 >= len(encoded) {
				return nil, fmt.Errorf("truncated %% escape")
			}
			hi, err := hexVal(encoded[i+1])
			if err != nil {
				return nil, err
			}
			lo, err := hexVal(encoded[i+2])
			if err != nil {
				return nil, err
			}
			out = append(out, patToken{ch: hi<<4 | lo})
			i += 2
		case ':', '/':
			return nil, fmt.Errorf("unencoded %q in segment name", string(c))
		default:
			out = append(out, patToken{ch: c})
		}
	}
	return out, nil
}

// decodeLiteral returns the plain name of an encoded segment, and reports
// false if the segment contains a wildcard and therefore has no single name.
func decodeLiteral(encoded string) (string, bool) {
	toks, err := compilePattern(encoded)
	if err != nil {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(toks))
	for _, t := range toks {
		if t.meta != 0 {
			return "", false
		}
		b.WriteByte(t.ch)
	}
	return b.String(), true
}

func hasMeta(encoded string) bool {
	for i := 0; i < len(encoded); i++ {
		switch encoded[i] {
		case '*', '?':
			return true
		case '%':
			i += 2
		}
	}
	return false
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("invalid %% escape digit %q", string(c))
}

// splitUnescaped splits on sep, skipping separators inside a percent escape.
func splitUnescaped(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '%':
			i += 2 // skip escape digits; validity is checked by compilePattern
		case sep:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// matchEncoded reports whether the encoded pattern matches the encoded
// candidate name. Both sides are decoded to literal bytes first, so a
// candidate written as %2A matches a pattern written as %2A, and '?' in the
// pattern matches exactly one decoded character rather than three raw bytes.
func matchEncoded(pattern, name string) bool {
	pat, err := compilePattern(pattern)
	if err != nil {
		return false
	}
	lit, ok := decodeLiteral(name)
	if !ok {
		// A candidate is expected to be concrete. A wildcard on that side only
		// matches an identical pattern, which callers handle by string equality.
		return pattern == name
	}
	return matchTokens(pat, lit)
}

// matchTokens is the classic linear wildcard match: greedy, with backtracking
// only to the most recent '*'. Avoids the exponential blowup that naive
// recursion hits on patterns like "a*a*a*b".
func matchTokens(pat []patToken, name string) bool {
	var (
		p, n         int
		starP, starN = -1, 0
	)
	for n < len(name) {
		switch {
		case p < len(pat) && pat[p].meta == '?':
			p++
			n++
		case p < len(pat) && pat[p].meta == 0 && pat[p].ch == name[n]:
			p++
			n++
		case p < len(pat) && pat[p].meta == '*':
			starP, starN = p, n
			p++ // try absorbing zero characters first
		case starP >= 0:
			starN++ // let the last '*' absorb one more character
			p, n = starP+1, starN
		default:
			return false
		}
	}
	for p < len(pat) && pat[p].meta == '*' {
		p++
	}
	return p == len(pat)
}
