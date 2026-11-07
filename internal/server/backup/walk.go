package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
)

// handler receives the data members of an archive while it is read.
// Bodies need not be consumed; the walker drains and hashes the rest.
type handler interface {
	// OnChunk gets one COPY chunk of a table. The chunks of one table arrive
	// consecutively and in order.
	OnChunk(table int, r io.Reader) error
	// OnTableEnd is called after the last chunk of a table (tables without
	// rows have no chunks and no call).
	OnTableEnd(table int) error
	// OnFile gets one content file.
	OnFile(rel string, size int64, r io.Reader) error
}

type noopHandler struct{}

func (noopHandler) OnChunk(int, io.Reader) error          { return nil }
func (noopHandler) OnTableEnd(int) error                  { return nil }
func (noopHandler) OnFile(string, int64, io.Reader) error { return nil }

// totalLimit fails once more than maxTotalBytes were read from the decrypted
// stream, whatever the tar headers claim.
type totalLimit struct {
	r io.Reader
	n int64
}

func (l *totalLimit) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.n += int64(n)
	if l.n > maxTotalBytes {
		return n, errors.New("archive is larger than the supported maximum")
	}
	return n, err
}

// ctxReader aborts reads once ctx is done.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// body reads one member while hashing it and counting COPY rows. In the COPY
// text format a raw newline only ever ends a row (newlines inside values are
// escaped), so counting them gives the row count without parsing.
type body struct {
	r    io.Reader
	h    hash.Hash
	n    int64
	rows int64
	last byte
}

func (b *body) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if n > 0 {
		b.h.Write(p[:n])
		b.n += int64(n)
		b.rows += int64(bytes.Count(p[:n], []byte{'\n'}))
		b.last = p[n-1]
	}
	return n, err
}

type walker struct {
	tr      *tar.Reader
	total   *totalLimit
	hdr     *Header
	hdrRaw  []byte
	members []Member
	seen    map[string]bool
}

// newWalker reads the tar stream inside an already decrypted age stream.
func newWalker(decrypted io.Reader) *walker {
	tl := &totalLimit{r: decrypted}
	return &walker{tr: tar.NewReader(tl), total: tl, seen: map[string]bool{}}
}

// next returns the next tar header after structural checks.
func (w *walker) next() (*tar.Header, memberID, error) {
	h, err := w.tr.Next()
	if err != nil {
		return nil, memberID{}, err
	}
	if len(w.members) >= maxMembers {
		return nil, memberID{}, fmt.Errorf("archive has more than %d members", maxMembers)
	}
	if h.Typeflag != tar.TypeReg {
		return nil, memberID{}, fmt.Errorf("archive member %q is not a regular file (links, directories and devices are not allowed)", h.Name)
	}
	for k := range h.PAXRecords {
		if strings.HasPrefix(k, "GNU.sparse") {
			return nil, memberID{}, fmt.Errorf("archive member %q is a sparse file", h.Name)
		}
	}
	if h.Size < 0 {
		return nil, memberID{}, fmt.Errorf("archive member %q has a negative size", h.Name)
	}
	if len(h.Name) > maxNameLen+len(prefixFiles) {
		return nil, memberID{}, errors.New("archive member name too long")
	}
	id, err := classify(h.Name)
	if err != nil {
		return nil, memberID{}, err
	}
	if w.seen[h.Name] {
		return nil, memberID{}, fmt.Errorf("duplicate archive member %q", h.Name)
	}
	w.seen[h.Name] = true
	limit := int64(maxChunkBytes)
	switch id.kind {
	case kindHeader:
		limit = maxHeaderBytes
	case kindManifest:
		limit = maxManifestBytes
	case kindFile:
		limit = maxFileBytes
	case kindChunk:
		if id.seq > maxChunkSeq {
			return nil, memberID{}, errors.New("too many chunks in one table")
		}
		if h.Size == 0 {
			return nil, memberID{}, fmt.Errorf("archive member %q is empty", h.Name)
		}
	}
	if h.Size > limit {
		return nil, memberID{}, fmt.Errorf("archive member %q is larger than the allowed %d bytes", h.Name, limit)
	}
	return h, id, nil
}

func (w *walker) open(h *tar.Header) *body {
	return &body{r: io.LimitReader(w.tr, h.Size), h: sha256.New()}
}

func (w *walker) finish(h *tar.Header, b *body) error {
	if _, err := io.Copy(io.Discard, b); err != nil {
		return fmt.Errorf("reading %s: %w", h.Name, unexpected(err))
	}
	if b.n != h.Size {
		return fmt.Errorf("archive member %q is truncated", h.Name)
	}
	w.members = append(w.members, Member{Name: h.Name, Size: b.n, SHA256: hexSum(b.h.Sum(nil))})
	return nil
}

func unexpected(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// readHeader reads and validates the first member, header.json.
func (w *walker) readHeader() (*Header, error) {
	h, id, err := w.next()
	if errors.Is(err, io.EOF) {
		return nil, errors.New("archive is empty")
	}
	if err != nil {
		return nil, err
	}
	if id.kind != kindHeader {
		return nil, fmt.Errorf("archive does not start with %s (found %q)", memberHeader, h.Name)
	}
	b := w.open(h)
	raw, err := io.ReadAll(b)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", memberHeader, unexpected(err))
	}
	if err := w.finish(h, b); err != nil {
		return nil, err
	}
	hdr, err := decodeHeader(raw)
	if err != nil {
		return nil, err
	}
	w.hdr, w.hdrRaw = hdr, raw
	return hdr, nil
}

// run reads the rest of the archive, feeding h, then checks the manifest
// against what was actually read. A nil error means every member is exactly
// what the manifest says and the encrypted stream was read to its authenticated end.
func (w *walker) run(h handler) (*Manifest, error) {
	if w.hdr == nil {
		return nil, errors.New("internal error: header not read")
	}
	rows := make(map[int]int64)
	var content ContentInfo
	cur, lastSeq, highest := -1, 0, -1
	inFiles := false
	endTable := func() error {
		if cur < 0 {
			return nil
		}
		t := cur
		cur = -1
		return h.OnTableEnd(t)
	}
	var manifest *Manifest
loop:
	for {
		th, id, err := w.next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("archive ends without a manifest (truncated?)")
		}
		if err != nil {
			return nil, err
		}
		switch id.kind {
		case kindHeader:
			return nil, errors.New("duplicate header")
		case kindChunk:
			if inFiles {
				return nil, fmt.Errorf("archive member %q is out of order", th.Name)
			}
			if id.table >= len(w.hdr.Tables) {
				return nil, fmt.Errorf("archive member %q names a table that is not in the header", th.Name)
			}
			if id.table != cur {
				if id.table <= highest {
					return nil, fmt.Errorf("archive member %q is out of order", th.Name)
				}
				if err := endTable(); err != nil {
					return nil, err
				}
				cur, lastSeq, highest = id.table, 0, id.table
			}
			if id.seq != lastSeq+1 {
				return nil, fmt.Errorf("archive member %q is out of sequence", th.Name)
			}
			lastSeq = id.seq
			b := w.open(th)
			if err := h.OnChunk(id.table, b); err != nil {
				return nil, err
			}
			if err := w.finish(th, b); err != nil {
				return nil, err
			}
			if b.last != '\n' {
				return nil, fmt.Errorf("archive member %q does not end at a row boundary", th.Name)
			}
			rows[id.table] += b.rows
		case kindFile:
			if err := endTable(); err != nil {
				return nil, err
			}
			inFiles = true
			b := w.open(th)
			if err := h.OnFile(id.rel, th.Size, b); err != nil {
				return nil, err
			}
			if err := w.finish(th, b); err != nil {
				return nil, err
			}
			content.Files++
			content.Bytes += th.Size
		case kindManifest:
			if err := endTable(); err != nil {
				return nil, err
			}
			b := w.open(th)
			raw, err := io.ReadAll(b)
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", memberManifest, unexpected(err))
			}
			if b.n != th.Size {
				return nil, errors.New("manifest is truncated")
			}
			manifest, err = decodeManifest(raw)
			if err != nil {
				return nil, err
			}
			break loop
		}
	}
	// Nothing may follow the manifest, and the encrypted stream must end
	// cleanly: only then has age authenticated the final chunk.
	if _, err := w.tr.Next(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("archive has members after the manifest")
		}
		return nil, fmt.Errorf("reading archive end: %w", unexpected(err))
	}
	n, err := io.Copy(io.Discard, io.LimitReader(w.total, maxTrailing+1))
	if err != nil {
		return nil, fmt.Errorf("reading archive end: %w", unexpected(err))
	}
	if n > maxTrailing {
		return nil, errors.New("archive has trailing data after the manifest")
	}
	if err := w.check(manifest, rows, content); err != nil {
		return nil, err
	}
	return manifest, nil
}

// check compares the manifest with what was read.
func (w *walker) check(m *Manifest, rows map[int]int64, content ContentInfo) error {
	a, _ := json.Marshal(m.Header)
	if !bytes.Equal(a, headerCanonical(w.hdrRaw)) {
		return errors.New("manifest and header disagree")
	}
	if len(m.Members) != len(w.members) {
		return fmt.Errorf("manifest lists %d members but the archive holds %d", len(m.Members), len(w.members))
	}
	for i, got := range w.members {
		if want := m.Members[i]; want != got {
			if want.Name != got.Name {
				return fmt.Errorf("manifest member %d is %q but the archive has %q", i, want.Name, got.Name)
			}
			return fmt.Errorf("integrity check failed for %s: the archive member does not match the manifest (sha256 or size differs)", got.Name)
		}
	}
	if len(m.RowCounts) != len(m.Tables) {
		return errors.New("manifest row counts do not match its table list")
	}
	for i, t := range m.Tables {
		want, ok := m.RowCounts[t.Name]
		if !ok {
			return fmt.Errorf("manifest has no row count for table %q", t.Name)
		}
		if got := rows[i]; got != want {
			return fmt.Errorf("table %q: manifest says %d rows, the archive holds %d", t.Name, want, got)
		}
	}
	if m.Content != content {
		return errors.New("manifest content summary does not match the archive")
	}
	return nil
}

// headerCanonical re-encodes header.json the way Header marshals so that the
// comparison is not sensitive to whitespace.
func headerCanonical(raw []byte) []byte {
	var h Header
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil
	}
	b, _ := json.Marshal(h)
	return b
}
