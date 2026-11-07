// Package masterkey creates, stores and shows the server's master key when the stack generates it itself (decision D109).
//
// The one-shot maintenance service creates the key on the first start of a new stack, in a volume that only it can write
// and the server reads. It never replaces a key: if the file is missing but the database already holds data sealed with
// a key, creating a new one would make that data unreadable, so it stops with an explanation instead.
package masterkey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/kek"
)

// Size is the length of the key in bytes.
const Size = 32

// ErrKeyMissing means the key file is gone but the database holds data that only that key can open.
var ErrKeyMissing = errors.New("the master key file is missing, but this database already holds data sealed with a master key: " +
	"restore the key (for example `maintenance set-master-key < your-saved-key.txt`), or reset the stack to start empty")

// Generate returns a new random key.
func Generate() ([]byte, error) {
	k := make([]byte, Size)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// Hex is the stored form of a key: 64 lower-case hexadecimal digits.
func Hex(key []byte) string { return hex.EncodeToString(key) }

// Grouped is the form shown to people: eight groups of eight digits, easier to read and to copy by hand.
func Grouped(key []byte) string {
	h := Hex(key)
	parts := make([]string, 0, 8)
	for i := 0; i < len(h); i += 8 {
		parts = append(parts, h[i:i+8])
	}
	return strings.Join(parts, "-")
}

// ID is the key's short fingerprint (see kek.Sealer.KeyID).
func ID(key []byte) (string, error) {
	s, err := kek.New(key)
	if err != nil {
		return "", err
	}
	return s.KeyID(), nil
}

var keyText = regexp.MustCompile(`(?i)(?:[0-9a-f]{8}-){7}[0-9a-f]{8}|[0-9a-f]{64}`)

// Parse finds a key in text: the grouped form, or 64 hexadecimal digits, anywhere in the input (so the saved
// text file can be given back as it is).
func Parse(text string) ([]byte, error) {
	m := keyText.FindString(text)
	if m == "" {
		return nil, errors.New("no master key found: expected 64 hexadecimal digits, with or without dashes")
	}
	k, err := hex.DecodeString(strings.ReplaceAll(m, "-", ""))
	if err != nil || len(k) != Size {
		return nil, errors.New("the master key is not 32 bytes of hexadecimal")
	}
	return k, nil
}

// WriteNew stores the key at path, refusing to replace an existing file. The file is for its owner only.
func WriteNew(path string, key []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) // #nosec G304 -- operator-supplied key path
	if err != nil {
		return err
	}
	if _, err := f.WriteString(Hex(key) + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// Provision makes a newly generated key permanent: it refuses when the database already holds sealed data, records the
// key so the console can ask the first administrator to save it, and writes the file. The record comes first, so a
// crash between the two steps is repaired by the next run (the row is replaced while it is still unacknowledged).
func Provision(ctx context.Context, db dbq.DBTX, path string, key []byte) error {
	q := dbq.New(db)
	holds, err := q.DatabaseHoldsSealedData(ctx)
	if err != nil {
		return fmt.Errorf("check the database before creating a master key: %w", err)
	}
	if holds {
		return ErrKeyMissing
	}
	id, err := ID(key)
	if err != nil {
		return err
	}
	if err := q.UpsertMasterKeyAck(ctx, id); err != nil {
		return fmt.Errorf("record the new master key: %w", err)
	}
	return WriteNew(path, key)
}
