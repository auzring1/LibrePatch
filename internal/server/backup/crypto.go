package backup

import (
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"io"
	"os"
	"strings"

	"filippo.io/age"
)

// MinPassphraseLen is the shortest passphrase accepted for new backups.
const MinPassphraseLen = 12

// ErrNoRecipient is returned when a backup would be written without any
// recipient or passphrase. Plaintext backups are never written.
var ErrNoRecipient = errors.New("refusing to write an unencrypted backup: give at least one --recipient / --recipient-file, or a --passphrase-file")

// ParseRecipient parses one age public key (age1... or age1pq1...).
func ParseRecipient(s string) (age.Recipient, error) {
	s = strings.TrimSpace(s)
	rs, err := age.ParseRecipients(strings.NewReader(s))
	if err != nil || len(rs) != 1 {
		// The input may be a secret key pasted by mistake: never echo it.
		return nil, errors.New("not a valid age recipient (expected a public key starting with age1)")
	}
	return rs[0], nil
}

// RecipientsFromFile reads an age recipients file (one key per line, # comments).
func RecipientsFromFile(path string) ([]age.Recipient, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	rs, err := age.ParseRecipients(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("recipient file %s: %w", path, err)
	}
	return rs, nil
}

// IdentitiesFromFile reads an age secret-key file.
func IdentitiesFromFile(path string) ([]age.Identity, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	ids, err := age.ParseIdentities(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("identity file %s: %w", path, err)
	}
	return ids, nil
}

// ReadPassphraseFile reads a passphrase from a file. A trailing newline is
// removed; nothing else is trimmed. Passphrases never come from argv.
func ReadPassphraseFile(path string, minLen int) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied path
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return "", err
	}
	if len(b) > 4096 {
		return "", errors.New("passphrase file is larger than 4 KiB")
	}
	p := strings.TrimRight(string(b), "\r\n")
	if p == "" {
		return "", fmt.Errorf("passphrase file %s is empty", path)
	}
	if len(p) < minLen {
		return "", fmt.Errorf("passphrase is shorter than %d characters", minLen)
	}
	return p, nil
}

// PassphraseRecipient returns an scrypt recipient. workFactor 0 keeps age's default.
func PassphraseRecipient(pass string, workFactor int) (age.Recipient, error) {
	r, err := age.NewScryptRecipient(pass)
	if err != nil {
		return nil, err
	}
	if workFactor > 0 {
		r.SetWorkFactor(workFactor)
	}
	return r, nil
}

// PassphraseIdentity returns an scrypt identity for restoring.
func PassphraseIdentity(pass string) (age.Identity, error) {
	return age.NewScryptIdentity(pass)
}

// decrypt opens an age stream. Errors are rewritten so that an operator can
// tell "wrong key" from "not a backup".
func decrypt(src io.Reader, ids []age.Identity) (io.Reader, error) {
	if len(ids) == 0 {
		return nil, errors.New("no identity or passphrase supplied for decryption")
	}
	r, err := age.Decrypt(src, ids...)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		if errors.As(err, &noMatch) {
			return nil, errors.New("cannot decrypt: the supplied key or passphrase does not match this backup")
		}
		return nil, fmt.Errorf("cannot decrypt (is this a %s backup?): %w", brand.Name, err)
	}
	return r, nil
}
