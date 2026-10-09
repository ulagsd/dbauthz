// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ulagsd/dbauthz/internal/version"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = Execute(t.Context(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVersionText(t *testing.T) {
	code, out, _ := run(t, "version")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.HasPrefix(out, "dbauthz ") {
		t.Errorf("output = %q, want prefix %q", out, "dbauthz ")
	}
}

func TestVersionJSON(t *testing.T) {
	code, out, _ := run(t, "version", "--output", "json")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	var info version.Info
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if info.Version == "" || info.Go == "" {
		t.Errorf("missing fields in %+v", info)
	}
}

func TestVersionRejectsUnknownFormat(t *testing.T) {
	code, _, errOut := run(t, "version", "--output", "yaml")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errOut, "unsupported output format") {
		t.Errorf("stderr = %q, want an unsupported-format error", errOut)
	}
}

func TestUnknownCommandFails(t *testing.T) {
	if code, _, _ := run(t, "no-such-command"); code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}
