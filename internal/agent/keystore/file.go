//go:build !windows

package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
)

var validName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// File stores keys as 0600 PEM files. DEVELOPMENT/TEST ONLY.
type File struct{ Dir string }

// Default returns the platform provider.
func Default(dataDir string) Provider { return &File{Dir: filepath.Join(dataDir, "keys")} }

func (f *File) path(name string) (string, error) {
	if !validName.MatchString(name) {
		return "", errors.New("invalid key name")
	}
	return filepath.Join(f.Dir, name+".pem"), nil
}

// Create implements Provider.
func (f *File) Create(name string) (crypto.Signer, string, error) {
	p, err := f.path(name)
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(f.Dir, 0o700); err != nil {
		return nil, "", err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, "", err
	}
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, "", err
	}
	return k, "file", nil
}

// Open implements Provider.
func (f *File) Open(name string) (crypto.Signer, error) {
	p, err := f.path(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p) // #nosec G304 -- validated name under our data dir
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("corrupt key file")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("not a signer")
	}
	return s, nil
}

// Delete implements Provider.
func (f *File) Delete(name string) error {
	p, err := f.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
