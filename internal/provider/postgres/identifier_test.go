package postgres

import (
	"strings"
	"testing"
)

func TestQuoteIdentifier(t *testing.T) {
	for _, tc := range []struct{ in, want, why string }{
		{"alice", `"alice"`, "ordinary name"},
		{"Alice", `"Alice"`, "quoting preserves case"},
		{`we"ird`, `"we""ird"`, "embedded quote is doubled"},
		{"drop table users", `"drop table users"`, "spaces are inert once quoted"},
		// The reason this function exists: identifiers cannot be bind
		// parameters, so a name is the one place injection could reach DDL.
		{`x"; DROP ROLE admin; --`, `"x""; DROP ROLE admin; --"`, "injection attempt stays one identifier"},
		{"ünïcode", `"ünïcode"`, "non-ascii is fine"},
	} {
		if got := QuoteIdentifier(tc.in); got != tc.want {
			t.Errorf("%s: QuoteIdentifier(%q) = %s, want %s", tc.why, tc.in, got, tc.want)
		}
	}
}

func TestQuoteLiteral(t *testing.T) {
	for _, tc := range []struct{ in, want, why string }{
		{"hello", `'hello'`, "ordinary literal"},
		{"it's", `'it''s'`, "embedded quote is doubled"},
		{`'; DROP ROLE admin; --`, `'''; DROP ROLE admin; --'`, "injection attempt stays one literal"},
		// A backslash means something different depending on
		// standard_conforming_strings, so force the unambiguous form.
		{`back\slash`, `E'back\\slash'`, "backslash forces the E'' form"},
	} {
		if got := QuoteLiteral(tc.in); got != tc.want {
			t.Errorf("%s: QuoteLiteral(%q) = %s, want %s", tc.why, tc.in, got, tc.want)
		}
	}
}

func TestValidateIdentifier(t *testing.T) {
	for _, ok := range []string{"alice", "app_ro", "Service-Account", "ünïcode", strings.Repeat("a", 63)} {
		if err := ValidateIdentifier(ok); err != nil {
			t.Errorf("ValidateIdentifier(%q) = %v, want nil", ok, err)
		}
	}
	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		// PostgreSQL truncates past 63 bytes, which would silently create a
		// different role than the one requested.
		{"too long", strings.Repeat("a", 64)},
		{"reserved prefix", "pg_readers"},
		{"reserved prefix, any case", "PG_readers"},
		{"leading space", " alice"},
		{"trailing space", "alice "},
		{"null byte", "al\x00ice"},
		{"control character", "al\tice"},
	} {
		if err := ValidateIdentifier(tc.in); err == nil {
			t.Errorf("%s: ValidateIdentifier(%q) was accepted", tc.name, tc.in)
		}
	}
}

// The two validators differ by exactly one rule, and that difference matters:
// db-iam must refuse to create a pg_ role but must be able to grant one.
func TestValidateIdentifierRefAllowsPredefinedRoles(t *testing.T) {
	for _, name := range []string{"pg_read_all_data", "pg_monitor", "PG_MONITOR"} {
		if err := ValidateIdentifierRef(name); err != nil {
			t.Errorf("ValidateIdentifierRef(%q) = %v; granting a predefined role is legitimate",
				name, err)
		}
		if err := ValidateIdentifier(name); err == nil {
			t.Errorf("ValidateIdentifier(%q) was accepted; db-iam must not create one", name)
		}
	}
}

// Everything else the two share must still be caught on the reference path.
func TestValidateIdentifierRefStillRejectsTheRest(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"too long", strings.Repeat("a", 64)},
		{"leading space", " app_ro"},
		{"trailing space", "app_ro "},
		{"null byte", "app\x00ro"},
		{"control character", "app\tro"},
	} {
		if err := ValidateIdentifierRef(tc.in); err == nil {
			t.Errorf("%s: ValidateIdentifierRef(%q) was accepted", tc.name, tc.in)
		}
	}
}
