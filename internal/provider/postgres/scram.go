package postgres

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/text/secure/precis"

	"github.com/ulagsd/db-iam/internal/secret"
)

// defaultSCRAMIterations matches PostgreSQL's own scram_iterations default.
//
// Raising it is tempting — modern guidance for password *storage* is orders of
// magnitude higher — but this cost is paid by the server on every single
// connection, not once at signup. Matching the server's default keeps
// authentication latency the same as any other role on the cluster; operators
// who have raised scram_iterations can raise this to match.
const defaultSCRAMIterations = 4096

const scramSaltBytes = 16

// SCRAMVerifier builds a PostgreSQL SCRAM-SHA-256 password verifier.
//
// This is the reason db-iam never sends a plaintext password to a server.
// CREATE ROLE ... PASSWORD 'literal' puts the password into the statement, and
// the statement into pg_stat_activity, into the server log whenever
// log_statement is on, and into any pooler or audit extension in the path.
// Handing over a precomputed verifier means the plaintext never leaves this
// process, and the server stores exactly what it would have derived anyway.
//
// Format, per PostgreSQL's parse_scram_secret:
//
//	SCRAM-SHA-256$<iterations>:<base64 salt>$<base64 StoredKey>:<base64 ServerKey>
func SCRAMVerifier(password secret.Text, iterations int) (string, error) {
	if iterations <= 0 {
		iterations = defaultSCRAMIterations
	}

	// RFC 5802 requires the password be prepared with SASLprep. For ASCII this
	// is the identity, but skipping it means a password with, say, a non-
	// breaking space would hash differently here than in a client that does
	// normalise, and the role simply could not log in.
	prepared, err := precis.OpaqueString.String(password.Reveal())
	if err != nil {
		return "", fmt.Errorf("password cannot be normalised for SCRAM (RFC 4013): %w", err)
	}

	salt := make([]byte, scramSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating SCRAM salt: %w", err)
	}

	saltedPassword, err := pbkdf2.Key(sha256.New, prepared, salt, iterations, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("deriving SCRAM salted password: %w", err)
	}

	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))

	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s",
		iterations, b64(salt), b64(storedKey[:]), b64(serverKey)), nil
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}
