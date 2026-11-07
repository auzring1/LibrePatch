package backup

import (
	"context"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

// Source opens an encrypted archive. Repeatable sources (files) can be
// opened again, which lets a restore verify the whole archive before it
// touches the database. Stdin cannot, so a streamed restore relies on its
// single transaction instead.
type Source struct {
	Open       func() (io.ReadCloser, error)
	Repeatable bool
}

// FileSource reads an archive from a file path ("-" means stdin).
func FileSource(path string, stdin io.Reader) Source {
	if path == "-" {
		used := false
		return Source{Open: func() (io.ReadCloser, error) {
			if used {
				return nil, fmt.Errorf("standard input can only be read once")
			}
			used = true
			return io.NopCloser(stdin), nil
		}}
	}
	return Source{Repeatable: true, Open: func() (io.ReadCloser, error) {
		return os.Open(path) // #nosec G304 -- operator-supplied path
	}}
}

// Verify decrypts an archive and checks every member against its manifest
// without touching any database. It returns the verified manifest.
func Verify(ctx context.Context, src Source, ids []age.Identity) (*Manifest, error) {
	rc, err := src.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	dec, err := decrypt(ctxReader{ctx, rc}, ids)
	if err != nil {
		return nil, err
	}
	w := newWalker(dec)
	if _, err := w.readHeader(); err != nil {
		return nil, err
	}
	return w.run(noopHandler{})
}
