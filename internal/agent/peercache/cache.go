// Package peercache lets agents on one network share the installers they have already downloaded (D126).
//
// Nothing here is trusted by anyone: a requester hashes what it receives and compares it with the SHA-256 in the signed
// job, exactly as for a vendor download. The cache only saves bandwidth. Files are stored by their SHA-256, so a request
// can name nothing but a hash, and a file is only ever served under the hash it was verified against.
package peercache

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Defaults.
const (
	DefaultMaxBytes = 2 << 30
	DefaultMaxAge   = 14 * 24 * time.Hour
	// MaxFileBytes is the largest installer that is kept (the same bound as a download).
	MaxFileBytes = 8 << 30
)

// Cache is a directory of verified files named by their SHA-256 (lower-case hex). It is safe for concurrent use.
type Cache struct {
	Dir      string
	MaxBytes int64         // total size; 0 = DefaultMaxBytes
	MaxAge   time.Duration // files not used for this long are removed; 0 = DefaultMaxAge
	Now      func() time.Time

	mu sync.Mutex
}

func (c *Cache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Cache) max() int64 {
	if c.MaxBytes > 0 {
		return c.MaxBytes
	}
	return DefaultMaxBytes
}

func (c *Cache) age() time.Duration {
	if c.MaxAge > 0 {
		return c.MaxAge
	}
	return DefaultMaxAge
}

// ErrBadHash: a hash is not 32 bytes.
var ErrBadHash = errors.New("peercache: not a SHA-256")

func name(sha []byte) (string, error) {
	if len(sha) != sha256.Size {
		return "", ErrBadHash
	}
	return hex.EncodeToString(sha), nil
}

// ParseName turns the hex name used in a request into a hash.
func ParseName(s string) ([]byte, error) {
	if len(s) != 2*sha256.Size {
		return nil, ErrBadHash
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return nil, ErrBadHash
		}
	}
	return hex.DecodeString(s)
}

// Put copies src into the cache under sha, hashing while it copies. A file whose content does not hash to sha is not kept.
// It evicts old files and, if needed, least recently used ones to stay within the size limit.
func (c *Cache) Put(src string, sha []byte) error {
	n, err := name(sha)
	if err != nil {
		return err
	}
	in, err := os.Open(src) // #nosec G304 -- a staged installer
	if err != nil {
		return err
	}
	defer in.Close()
	st, err := in.Stat()
	if err != nil {
		return err
	}
	if st.Size() > MaxFileBytes || st.Size() > c.max() {
		return fmt.Errorf("peercache: %d bytes is more than the cache keeps", st.Size())
	}
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.Dir, "put-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), in); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(h.Sum(nil), sha) != 1 {
		return errors.New("peercache: the file does not match its hash")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.Rename(tmp.Name(), filepath.Join(c.Dir, n)); err != nil {
		return err
	}
	_ = os.Chtimes(filepath.Join(c.Dir, n), c.now(), c.now())
	c.evictLocked()
	return nil
}

// Open returns the file cached under sha and marks it as used now. os.ErrNotExist when there is none.
func (c *Cache) Open(sha []byte) (*os.File, error) {
	n, err := name(sha)
	if err != nil {
		return nil, err
	}
	p := filepath.Join(c.Dir, n)
	f, err := os.Open(p) // #nosec G304 -- the name is 64 hex characters inside the cache directory
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, os.ErrNotExist
	}
	_ = os.Chtimes(p, c.now(), c.now())
	return f, nil
}

// Has reports whether a file is cached under sha.
func (c *Cache) Has(sha []byte) bool {
	f, err := c.Open(sha)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// Evict removes files that are too old and then the least recently used ones until the cache fits its limit.
func (c *Cache) Evict() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictLocked()
}

type entry struct {
	path string
	size int64
	used time.Time
}

func (c *Cache) evictLocked() {
	ents, err := os.ReadDir(c.Dir)
	if err != nil {
		return
	}
	var files []entry
	var total int64
	now := c.now()
	for _, e := range ents {
		p := filepath.Join(c.Dir, e.Name())
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if _, err := ParseName(e.Name()); err != nil { // a leftover temporary file or something foreign
			if now.Sub(info.ModTime()) > time.Hour {
				_ = os.Remove(p)
			}
			continue
		}
		if now.Sub(info.ModTime()) > c.age() {
			_ = os.Remove(p)
			continue
		}
		files = append(files, entry{p, info.Size(), info.ModTime()})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].used.Before(files[j].used) })
	for _, f := range files {
		if total <= c.max() {
			break
		}
		if os.Remove(f.path) == nil {
			total -= f.size
		}
	}
}

// Clear removes everything (the policy was switched off).
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	ents, _ := os.ReadDir(c.Dir)
	for _, e := range ents {
		_ = os.Remove(filepath.Join(c.Dir, e.Name()))
	}
}
