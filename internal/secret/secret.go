// Package secret holds values that must not be logged, printed or serialised.
package secret

import (
	"crypto/rand"
	"fmt"
	"strings"
	"unicode"
)

// Text is a secret string.
//
// It deliberately breaks the obvious ways a value leaks: fmt verbs, %v on a
// surrounding struct, slog, and encoding/json all see a placeholder. Reading
// the real value takes an explicit Reveal call, which is greppable in review.
type Text string

// String implements fmt.Stringer with a placeholder.
func (t Text) String() string { return "[redacted]" }

// GoString implements fmt.GoStringer, so %#v is safe too.
func (t Text) GoString() string { return "[redacted]" }

// MarshalJSON renders a placeholder, so a secret in a response struct cannot
// escape by being forgotten.
func (t Text) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

// LogValue implements slog.LogValuer.
func (t Text) LogValue() any { return "[redacted]" }

// Reveal returns the underlying value. Every call site is a place to ask
// whether the plaintext is really needed.
func (t Text) Reveal() string { return string(t) }

// Empty reports whether the secret is unset.
func (t Text) Empty() bool { return t == "" }

// MinPasswordLength is the shortest password accepted.
//
// Length is the only property worth enforcing. Composition rules (a digit, a
// symbol) push people towards predictable substitutions without adding real
// entropy, which is why NIST SP 800-63B dropped them.
const MinPasswordLength = 12

// ValidatePassword rejects passwords that are trivially weak.
func ValidatePassword(p Text, username string) error {
	s := p.Reveal()
	if len(s) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(s) > 1024 {
		return fmt.Errorf("password must be at most 1024 characters")
	}
	if strings.EqualFold(strings.TrimSpace(s), strings.TrimSpace(username)) {
		return fmt.Errorf("password must not be the username")
	}
	for _, r := range s {
		if r == 0 || unicode.IsControl(r) {
			return fmt.Errorf("password must not contain control characters")
		}
	}
	return nil
}

// passwordAlphabet omits characters that are misread when a password is copied
// by hand or out of a terminal: 0/O, 1/l/I. Losing them costs about four bits
// across a 24-character password, which the length more than covers.
const passwordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GeneratePassword returns a cryptographically random password.
//
// 24 characters from this 56-symbol alphabet is roughly 139 bits, which is far
// past anything that needs defending and costs nothing, since no human has to
// memorise a database role's password.
func GeneratePassword() (Text, error) {
	const length = 24
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating password: %w", err)
	}
	// rand.Read gives uniform bytes; 256 is not a multiple of 56, so fold the
	// bias out by resampling rather than taking a plain modulus.
	out := make([]byte, 0, length)
	for len(out) < length {
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("generating password: %w", err)
		}
		for _, v := range b {
			if len(out) == length {
				break
			}
			const limit = 256 - (256 % len(passwordAlphabet))
			if int(v) >= limit {
				continue // would skew the distribution
			}
			out = append(out, passwordAlphabet[int(v)%len(passwordAlphabet)])
		}
	}
	return Text(out), nil
}
