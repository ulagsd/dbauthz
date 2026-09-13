package postgres

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// PostgreSQL truncates identifiers at NAMEDATALEN-1 bytes. Accepting a longer
// name would silently create a different role than the one asked for, and the
// next reconcile would then try to create it again.
const maxIdentifierBytes = 63

// QuoteIdentifier renders s as a quoted SQL identifier.
//
// Identifiers cannot be bind parameters, so every identifier reaching a
// statement passes through here. Doubling the embedded quote is what makes a
// name containing " harmless; ValidateIdentifier separately refuses the cases
// that are better rejected than escaped.
func QuoteIdentifier(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// QuoteLiteral renders s as a single-quoted SQL string literal.
//
// Used only where a bind parameter is impossible, which in practice is DDL:
// CREATE ROLE ... PASSWORD and COMMENT ON take literals, not parameters. A
// backslash forces the E” form, because standard_conforming_strings can be
// off and the meaning of \ would then change under us.
func QuoteLiteral(s string) string {
	escaped := strings.ReplaceAll(s, `'`, `''`)
	if strings.ContainsRune(s, '\\') {
		return "E'" + strings.ReplaceAll(escaped, `\`, `\\`) + "'"
	}
	return "'" + escaped + "'"
}

// ValidateIdentifierRef checks a name that refers to something that already
// exists, such as a role being granted.
//
// Quoting makes an arbitrary name *safe*; these rules catch the cases where a
// technically-valid name would still be a mistake — one that PostgreSQL would
// truncate into a different object, or one carrying characters invisible in
// every tool that will display it.
//
// It deliberately permits the pg_ prefix: GRANT pg_read_all_data TO alice is a
// real thing operators do, and refusing to reference a role the server ships
// would make db-iam unable to express access people already grant by hand.
func ValidateIdentifierRef(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("name must not be empty")

	case len(name) > maxIdentifierBytes:
		return fmt.Errorf("name is %d bytes; PostgreSQL truncates at %d, "+
			"which would silently address a different role", len(name), maxIdentifierBytes)

	case !utf8.ValidString(name):
		return fmt.Errorf("name is not valid UTF-8")

	case strings.ContainsRune(name, 0):
		return fmt.Errorf("name must not contain a null byte")

	case strings.TrimSpace(name) != name:
		return fmt.Errorf("name has leading or trailing whitespace, which is "+
			"invisible in every tool that will display it: %q", name)
	}

	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("name must not contain control characters")
		}
	}
	return nil
}

// ValidateIdentifier checks a name db-iam is about to create.
//
// Stricter than ValidateIdentifierRef by exactly one rule: pg_ is reserved for
// the server's own predefined roles. PostgreSQL refuses to create one anyway,
// but failing here names the reason instead of surfacing a server error.
func ValidateIdentifier(name string) error {
	if err := ValidateIdentifierRef(name); err != nil {
		return err
	}
	if strings.HasPrefix(strings.ToLower(name), "pg_") {
		return fmt.Errorf("names beginning with pg_ are reserved for PostgreSQL")
	}
	return nil
}
