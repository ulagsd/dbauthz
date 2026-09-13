package postgres

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"github.com/ulagsd/db-iam/internal/secret"
)

// parseVerifier splits PostgreSQL's verifier format:
//
//	SCRAM-SHA-256$<iterations>:<salt>$<storedKey>:<serverKey>
func parseVerifier(t *testing.T, v string) (iter int, salt, stored, server []byte) {
	t.Helper()

	rest, ok := strings.CutPrefix(v, "SCRAM-SHA-256$")
	if !ok {
		t.Fatalf("verifier %q has the wrong prefix", v)
	}
	head, tail, ok := strings.Cut(rest, "$")
	if !ok {
		t.Fatalf("verifier %q has no $ between the salt and the keys", v)
	}
	iterStr, saltB64, ok := strings.Cut(head, ":")
	if !ok {
		t.Fatalf("verifier %q has no : between iterations and salt", v)
	}
	storedB64, serverB64, ok := strings.Cut(tail, ":")
	if !ok {
		t.Fatalf("verifier %q has no : between the keys", v)
	}

	var err error
	if iter, err = strconv.Atoi(iterStr); err != nil {
		t.Fatalf("iterations %q: %v", iterStr, err)
	}
	dec := func(s string) []byte {
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("base64 %q: %v", s, err)
		}
		return b
	}
	return iter, dec(saltB64), dec(storedB64), dec(serverB64)
}

// The verifier must be exactly what PostgreSQL would have derived itself, or
// the role is created and simply cannot log in. Recomputing the RFC 5802
// derivation independently is the only way to know that without a server.
func TestSCRAMVerifierMatchesRFC5802Derivation(t *testing.T) {
	const password = "correct-horse-battery-staple"

	v, err := SCRAMVerifier(secret.Text(password), 0)
	if err != nil {
		t.Fatalf("SCRAMVerifier: %v", err)
	}
	iter, salt, stored, server := parseVerifier(t, v)

	if iter != defaultSCRAMIterations {
		t.Errorf("iterations = %d, want %d (PostgreSQL's own default)", iter, defaultSCRAMIterations)
	}
	if len(salt) != scramSaltBytes {
		t.Errorf("salt is %d bytes, want %d", len(salt), scramSaltBytes)
	}

	saltedPassword, err := pbkdf2.Key(sha256.New, password, salt, iter, sha256.Size)
	if err != nil {
		t.Fatalf("pbkdf2: %v", err)
	}
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	wantStored := sha256.Sum256(clientKey)
	wantServer := hmacSHA256(saltedPassword, []byte("Server Key"))

	if !hmac.Equal(stored, wantStored[:]) {
		t.Error("StoredKey does not match SHA256(HMAC(SaltedPassword, \"Client Key\"))")
	}
	if !hmac.Equal(server, wantServer) {
		t.Error("ServerKey does not match HMAC(SaltedPassword, \"Server Key\")")
	}
}

// A fresh salt per call is what stops two roles with the same password from
// sharing a verifier.
func TestSCRAMVerifierSaltsEveryCall(t *testing.T) {
	a, err := SCRAMVerifier("same-password-here", 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SCRAMVerifier("same-password-here", 0)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("the same password produced the same verifier; the salt is not random")
	}
}

func TestSCRAMVerifierHonoursIterations(t *testing.T) {
	v, err := SCRAMVerifier("a-perfectly-fine-password", 8192)
	if err != nil {
		t.Fatal(err)
	}
	if iter, _, _, _ := parseVerifier(t, v); iter != 8192 {
		t.Errorf("iterations = %d, want 8192", iter)
	}
}

// SASLprep is not cosmetic: a client that normalises and a server that does not
// derive different keys, and the role cannot authenticate.
func TestSCRAMVerifierNormalisesThePassword(t *testing.T) {
	// U+00A0 NO-BREAK SPACE maps to a plain space under RFC 4013.
	withNbsp, err := SCRAMVerifier(secret.Text("pass word-long"), 0)
	if err != nil {
		t.Fatalf("SCRAMVerifier: %v", err)
	}
	iter, salt, stored, _ := parseVerifier(t, withNbsp)

	// Re-derive using the plain-space form and the same salt.
	saltedPassword, err := pbkdf2.Key(sha256.New, "pass word-long", salt, iter, sha256.Size)
	if err != nil {
		t.Fatal(err)
	}
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	want := sha256.Sum256(clientKey)

	if !hmac.Equal(stored, want[:]) {
		t.Error("the no-break space was not normalised to a space; " +
			"a normalising client would fail to authenticate")
	}
}
