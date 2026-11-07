package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"strings"
)

const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no 0/o/1/l/i

// RecoveryCodeCount is how many codes are issued at MFA enrollment.
const RecoveryCodeCount = 10

// NewRecoveryCodes returns n codes like "abcd-efgh-jkmn" (~59 bits each).
func NewRecoveryCodes(n int) ([]string, error) {
	codes := make([]string, n)
	buf := make([]byte, 12)
	for i := range codes {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		var b strings.Builder
		for j, c := range buf {
			if j > 0 && j%4 == 0 {
				b.WriteByte('-')
			}
			// 31-symbol alphabet; modulo bias is negligible for 256 % 31 = 8.
			b.WriteByte(recoveryAlphabet[int(c)%len(recoveryAlphabet)])
		}
		codes[i] = b.String()
	}
	return codes, nil
}

// NormalizeRecoveryCode strips separators/whitespace and lowercases.
func NormalizeRecoveryCode(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.NewReplacer("-", "", " ", "").Replace(s)
}

// HashRecoveryCode hashes a (normalized) code. Codes are high-entropy random
// values, so a fast hash is appropriate.
func HashRecoveryCode(code string) []byte {
	s := sha256.Sum256([]byte("librepatch/recovery/v1\x00" + NormalizeRecoveryCode(code)))
	return s[:]
}

// LooksLikeRecoveryCode distinguishes recovery codes from 6-digit TOTP codes.
func LooksLikeRecoveryCode(s string) bool { return len(NormalizeRecoveryCode(s)) == 12 }

// EnrollmentTokenHash is the stored hash of an enrollment token secret.
// Tokens are 256-bit random values, so a fast hash is appropriate.
func EnrollmentTokenHash(secret string) []byte {
	h := sha256.Sum256([]byte("librepatch/enroll-token/v1\x00" + secret))
	return h[:]
}
