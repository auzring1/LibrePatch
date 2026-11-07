package catalog

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

// ErrTooLarge means an upload exceeded the size limit.
var ErrTooLarge = errors.New("catalog: upload too large")

// Store keeps uploaded installers on disk, addressed by SHA-256 and separated by
// organization: <dir>/<org>/<hex sha256>. Files are written once.
type Store struct {
	Dir string
}

func (s *Store) path(org uuid.UUID, sha []byte) (string, error) {
	if s.Dir == "" {
		return "", errors.New("content storage is not configured")
	}
	if len(sha) != 32 {
		return "", errors.New("bad hash")
	}
	return filepath.Join(s.Dir, org.String(), hex.EncodeToString(sha)), nil
}

// Put streams r into the store and returns its SHA-256 and size. At most max
// bytes are accepted. The file only becomes visible once complete.
func (s *Store) Put(org uuid.UUID, r io.Reader, max int64) (sha []byte, size int64, err error) {
	if s.Dir == "" {
		return nil, 0, errors.New("content storage is not configured")
	}
	odir := filepath.Join(s.Dir, org.String())
	if err := os.MkdirAll(odir, 0o700); err != nil {
		return nil, 0, err
	}
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(odir, ".upload-"+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- inside the content directory
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(r, max+1))
	if err != nil {
		return nil, 0, err
	}
	if n > max {
		return nil, 0, ErrTooLarge
	}
	if n == 0 {
		return nil, 0, errors.New("empty upload")
	}
	// Durable before it gets its final name: a file named after its hash is trusted without being hashed again, so a crash
	// must not leave a short one behind under that name.
	if err := f.Sync(); err != nil {
		return nil, 0, err
	}
	if err := f.Close(); err != nil {
		return nil, 0, err
	}
	sum := h.Sum(nil)
	final, err := s.path(org, sum)
	if err != nil {
		return nil, 0, err
	}
	if _, err := os.Stat(final); err == nil {
		return sum, n, nil // identical content already stored
	}
	if err := os.Rename(tmp, final); err != nil {
		return nil, 0, err
	}
	return sum, n, nil
}

// Open returns the stored file and its size.
func (s *Store) Open(org uuid.UUID, sha []byte) (*os.File, int64, error) {
	p, err := s.path(org, sha)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p) // #nosec G304 -- path built from a UUID and a hex hash
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, fi.Size(), nil
}

// Delete removes a stored file (used when the last reference goes away).
func (s *Store) Delete(org uuid.UUID, sha []byte) error {
	p, err := s.path(org, sha)
	if err != nil {
		return err
	}
	return os.Remove(p)
}
