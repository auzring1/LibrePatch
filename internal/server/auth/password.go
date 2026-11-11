// Package auth implements password hashing, password policy, TOTP MFA,
// recovery codes, sessions, rate limiting and RBAC for the web console.
package auth

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (OWASP-compliant, above the minimum m=19MiB,t=2,p=1).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16

	// MinPasswordLen / MaxPasswordLen bound admin passwords (runes).
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// hashSlots bounds concurrent argon2id computations (64 MiB each) so a burst
// of logins cannot exhaust memory.
var hashSlots = make(chan struct{}, 4)

// HashPassword returns an argon2id PHC string.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hashSlots <- struct{}{}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	<-hashSlots
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// dummyHash equalizes timing when the user does not exist.
var dummyHash = sync.OnceValue(func() string {
	h, _ := HashPassword("librepatch-dummy-password-for-timing")
	return h
})

// VerifyPassword checks pw against a PHC string in constant time.
// Pass encoded == "" for unknown users: it still burns the same CPU. A stored value that is not a usable hash (an account
// without a password, a damaged row) costs the same too, so the time taken says nothing about the account.
func VerifyPassword(pw, encoded string) bool {
	h, ok := parseHash(encoded)
	if !ok {
		h, _ = parseHash(dummyHash())
		pw += "\x00never-matches"
	}
	hashSlots <- struct{}{}
	got := argon2.IDKey([]byte(pw), h.salt, h.t, h.m, h.p, uint32(len(h.want))) // #nosec G115 -- len(want) <= 64 checked in parseHash
	<-hashSlots
	return subtle.ConstantTimeCompare(got, h.want) == 1 && ok
}

// phc is a parsed argon2id PHC string.
type phc struct {
	m, t uint32
	p    uint8
	salt []byte
	want []byte
}

// parseHash reads an argon2id PHC string. ok is false for anything else, including "".
func parseHash(encoded string) (h phc, ok bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return h, false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return h, false
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.m, &h.t, &h.p); err != nil {
		return h, false
	}
	// Refuse absurd parameters from a corrupted/hostile row.
	if h.m > 1024*1024 || h.t > 20 || h.p == 0 || h.p > 16 {
		return h, false
	}
	var err error
	if h.salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return h, false
	}
	if h.want, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(h.want) == 0 || len(h.want) > 64 {
		return h, false
	}
	return h, true
}

// NeedsRehash reports whether a hash uses outdated parameters.
func NeedsRehash(encoded string) bool {
	return !strings.HasPrefix(encoded, fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$", argon2.Version, argonMemory, argonTime, argonThreads))
}

// common-passwords.txt.gz: lowercase entries of 12-64 characters from the
// SecLists xato-net 1M list (MIT license, see THIRD_PARTY_NOTICES.md).
//
//go:embed common-passwords.txt.gz
var commonGz []byte

var commonPasswords = sync.OnceValue(func() map[string]struct{} {
	m := make(map[string]struct{}, 50000)
	zr, err := gzip.NewReader(bytes.NewReader(commonGz))
	if err != nil {
		return m
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		m[sc.Text()] = struct{}{}
	}
	return m
})

// ErrWeakPassword is returned by ValidatePassword.
var ErrWeakPassword = errors.New("weak password")

// ValidatePassword enforces the password policy (NIST SP 800-63B style:
// length and breach-list checks, no composition rules).
func ValidatePassword(pw, email string) error { return ValidatePasswordMin(pw, email, MinPasswordLen) }

// ValidatePasswordMin is ValidatePassword with a longer minimum chosen by the organization (never below
// MinPasswordLen).
func ValidatePasswordMin(pw, email string, min int) error {
	if min < MinPasswordLen {
		min = MinPasswordLen
	}
	n := utf8.RuneCountInString(pw)
	switch {
	case !utf8.ValidString(pw):
		return fmt.Errorf("%w: password must be valid UTF-8", ErrWeakPassword)
	case n < min:
		return fmt.Errorf("%w: use at least %d characters", ErrWeakPassword, min)
	case n > MaxPasswordLen:
		return fmt.Errorf("%w: use at most %d characters", ErrWeakPassword, MaxPasswordLen)
	}
	lower := strings.ToLower(pw)
	if email != "" {
		local := strings.ToLower(strings.SplitN(email, "@", 2)[0])
		if lower == strings.ToLower(email) || (len(local) >= 4 && strings.Contains(lower, local) && n-len(local) < 8) {
			return fmt.Errorf("%w: password is too similar to the email address", ErrWeakPassword)
		}
	}
	if _, bad := commonPasswords()[lower]; bad {
		return fmt.Errorf("%w: this password appears in public breach lists", ErrWeakPassword)
	}
	if allSameRune(pw) {
		return fmt.Errorf("%w: password is a repeated character", ErrWeakPassword)
	}
	return nil
}

func allSameRune(s string) bool {
	first, _ := utf8.DecodeRuneInString(s)
	for _, r := range s {
		if r != first {
			return false
		}
	}
	return true
}
