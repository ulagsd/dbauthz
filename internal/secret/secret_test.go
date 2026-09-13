package secret

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The type exists to make leaking hard, so check each way a value escapes.
func TestTextIsRedactedEveryWayItCouldEscape(t *testing.T) {
	s := Text("hunter2")

	// Held as any so these go through fmt's runtime dispatch, which is the
	// path a careless caller actually takes. Passing the typed value would let
	// a linter rewrite them into String() and test nothing.
	var boxed any = s

	for name, got := range map[string]string{
		"String":      s.String(),
		"%v":          fmt.Sprintf("%v", boxed),
		"%s":          fmt.Sprintf("%s", boxed),
		"%#v":         fmt.Sprintf("%#v", boxed),
		"in a struct": fmt.Sprintf("%v", struct{ P Text }{s}),
	} {
		if strings.Contains(got, "hunter2") {
			t.Errorf("%s leaked the secret: %s", name, got)
		}
	}

	body, err := json.Marshal(struct {
		Password Text `json:"password"`
	}{s})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "hunter2") {
		t.Errorf("JSON leaked the secret: %s", body)
	}
	if s.Reveal() != "hunter2" {
		t.Error("Reveal should return the real value")
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("a-perfectly-fine-password", "alice"); err != nil {
		t.Errorf("rejected a good password: %v", err)
	}
	for _, tc := range []struct {
		name string
		pw   Text
		user string
	}{
		{"too short", "short", "alice"},
		{"empty", "", "alice"},
		{"same as username", "averylongusername", "averylongusername"},
		{"same as username, different case", "AVERYLONGUSERNAME", "averylongusername"},
		{"control character", "long-enough\x00pass", "alice"},
	} {
		if err := ValidatePassword(tc.pw, tc.user); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		p, err := GeneratePassword()
		if err != nil {
			t.Fatal(err)
		}
		s := p.Reveal()
		if len(s) != 24 {
			t.Fatalf("length = %d, want 24", len(s))
		}
		if seen[s] {
			t.Fatal("GeneratePassword repeated itself")
		}
		seen[s] = true

		for _, r := range s {
			if !strings.ContainsRune(passwordAlphabet, r) {
				t.Fatalf("character %q is outside the alphabet", r)
			}
		}
		if err := ValidatePassword(p, "alice"); err != nil {
			t.Fatalf("generated a password its own validator rejects: %v", err)
		}
	}
}
