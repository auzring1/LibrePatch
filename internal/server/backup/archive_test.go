package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestCraftedValidArchiveVerifies(t *testing.T) {
	id, rcp := genKey(t)
	a := craft(t, rcp, fakeHeader(), []tarMember{{name: "files/org/ok", data: []byte("hello")}}, nil)
	m, err := Verify(context.Background(), bytesSource(a, true), []age.Identity{id})
	if err != nil || m.Content.Files != 1 {
		t.Fatalf("%+v %v", m, err)
	}
}

func TestUnsafeMemberNamesAndTypesAreRefused(t *testing.T) {
	id, rcp := genKey(t)
	long := strings.Repeat("x", 300)
	cases := map[string]tarMember{
		"dotdot":        {name: "files/../evil"},
		"nested dotdot": {name: "files/a/../../evil"},
		"dot":           {name: "files/./x"},
		"double slash":  {name: "files//x"},
		"absolute":      {name: "files//etc/passwd"},
		"toplevel abs":  {name: "/etc/passwd"},
		"outside tree":  {name: "evil"},
		"hidden":        {name: "files/.hidden"},
		"backslash":     {name: `files/a\b`},
		"colon":         {name: "files/c:evil"},
		"control char":  {name: "files/a\x01b"},
		"long part":     {name: "files/" + long},
		"deep":          {name: "files/" + strings.Repeat("a/", 20) + "b"},
		"symlink":       {name: "files/link", typeflag: tar.TypeSymlink, link: "/etc/passwd"},
		"hardlink":      {name: "files/hard", typeflag: tar.TypeLink, link: "files/ok"},
		"directory":     {name: "files/d", typeflag: tar.TypeDir},
		"fifo":          {name: "files/f", typeflag: tar.TypeFifo},
		"bad chunk":     {name: "db/t0000/000000.copy", data: []byte("x\n")},
		"chunk name":    {name: "db/t0000/1.copy", data: []byte("x\n")},
		"chunk escape":  {name: "db/../x", data: []byte("x\n")},
	}
	for name, m := range cases {
		a := craft(t, rcp, fakeHeader(), []tarMember{m}, nil)
		if _, err := Verify(context.Background(), bytesSource(a, true), []age.Identity{id}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// duplicate members
	a := craft(t, rcp, fakeHeader(), []tarMember{{name: "files/a", data: []byte("1")}, {name: "files/a", data: []byte("2")}}, nil)
	if _, err := Verify(context.Background(), bytesSource(a, true), []age.Identity{id}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate: %v", err)
	}
	// header missing / not first
	a = encryptTar(t, rcp, []tarMember{{name: "files/a", data: []byte("1")}})
	if _, err := Verify(context.Background(), bytesSource(a, true), []age.Identity{id}); err == nil {
		t.Error("archive without header accepted")
	}
}

// Nothing is written outside the content directory by a hostile archive.
func TestTraversalWritesNothingOutside(t *testing.T) {
	ctx := context.Background()
	id, rcp := genKey(t)
	parent := t.TempDir()
	contentDir := filepath.Join(parent, "content")
	hdr := Header{FormatVersion: FormatVersion, AppVersion: "t", SchemaVersion: 1, CreatedAt: fakeHeader().CreatedAt, Notes: []string{},
		Tables: fakeHeader().Tables, Sequences: []SeqDef{}}
	for _, name := range []string{"files/../evil", "files//abs", "files/a/../../evil"} {
		a := craft(t, rcp, hdr, []tarMember{{name: name, data: []byte("pwned")}}, nil)
		dst := newEmptyDB(t)
		_, err := Restore(ctx, RestoreOptions{DatabaseURL: dst, ContentDir: contentDir, Source: bytesSource(a, false), Identities: []age.Identity{id}, Log: discard})
		if err == nil {
			t.Fatalf("%s: restore succeeded", name)
		}
		assertNoRows(t, dst)
		ents, _ := os.ReadDir(parent)
		for _, e := range ents {
			if e.Name() != "content" {
				t.Fatalf("%s: wrote %s outside the content dir", name, e.Name())
			}
		}
		if inner, _ := os.ReadDir(contentDir); len(inner) != 0 {
			t.Fatalf("%s: left files in the content dir: %v", name, inner)
		}
	}
}

func TestSizeCapsAreEnforcedFromHeaders(t *testing.T) {
	// A header that declares an enormous member is refused before any data is read.
	for name, size := range map[string]int64{"files/big": maxFileBytes + 1, "db/t0000/000001.copy": maxChunkBytes + 1, memberManifest: maxManifestBytes + 1} {
		var raw bytes.Buffer
		tw := tar.NewWriter(&raw)
		rawH, _ := json.Marshal(fakeHeader())
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: memberHeader, Size: int64(len(rawH))})
		_, _ = tw.Write(rawH)
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Size: size})
		w := newWalker(bytes.NewReader(raw.Bytes()))
		if _, err := w.readHeader(); err != nil {
			t.Fatal(err)
		}
		if _, err := w.run(noopHandler{}); err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An oversized header member.
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: memberHeader, Size: maxHeaderBytes + 1})
	if _, err := newWalker(bytes.NewReader(raw.Bytes())).readHeader(); err == nil {
		t.Error("oversized header accepted")
	}
}

func TestHeaderValidation(t *testing.T) {
	good := fakeHeader()
	b, _ := json.Marshal(good)
	if _, err := decodeHeader(b); err != nil {
		t.Fatal(err)
	}
	mut := func(f func(*Header)) []byte {
		h := fakeHeader()
		f(&h)
		b, _ := json.Marshal(h)
		return b
	}
	bad := map[string][]byte{
		"no tables":   mut(func(h *Header) { h.Tables = nil }),
		"dup table":   mut(func(h *Header) { h.Tables = append(h.Tables, h.Tables[0]) }),
		"no columns":  mut(func(h *Header) { h.Tables[0].Columns = nil }),
		"dup column":  mut(func(h *Header) { h.Tables[0].Columns = []string{"a", "a"} }),
		"bad kind":    mut(func(h *Header) { h.Tables[0].Kind = "view" }),
		"no schema":   mut(func(h *Header) { h.SchemaVersion = 0 }),
		"unknown key": []byte(strings.Replace(string(b), `{`, `{"evil":1,`, 1)),
		"trailing":    append(bytes.Clone(b), []byte(`{}`)...),
		"not json":    []byte("hello"),
	}
	for name, data := range bad {
		if _, err := decodeHeader(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestChunkerSplitsOnRowBoundaries(t *testing.T) {
	var out bytes.Buffer
	aw := &archiveWriter{tw: tar.NewWriter(&out)}
	ch := &chunker{aw: aw, table: 3}
	var want bytes.Buffer
	row := strings.Repeat("x", 1000) + "\\n" + strings.Repeat("y", 30) + "\n" // escaped newline inside a value, raw newline ends the row
	for want.Len() < 2*chunkSize+12345 {
		want.WriteString(row)
	}
	data := want.Bytes()
	for len(data) > 0 { // feed in odd sized writes
		n := min(len(data), 70_001)
		if _, err := ch.Write(data[:n]); err != nil {
			t.Fatal(err)
		}
		data = data[n:]
	}
	if err := ch.close(); err != nil {
		t.Fatal(err)
	}
	if err := aw.tw.Close(); err != nil {
		t.Fatal(err)
	}
	if ch.rows != int64(strings.Count(want.String(), "\n")) {
		t.Fatalf("rows = %d", ch.rows)
	}
	tr := tar.NewReader(&out)
	var got bytes.Buffer
	n := 0
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		n++
		if h.Name != chunkName(3, n) || h.Size > chunkSize+70_001+int64(len(row)) {
			t.Fatalf("chunk %d: %s size %d", n, h.Name, h.Size)
		}
		var b bytes.Buffer
		_, _ = b.ReadFrom(tr)
		if b.Bytes()[b.Len()-1] != '\n' {
			t.Fatal("chunk does not end at a row boundary")
		}
		got.Write(b.Bytes())
	}
	if n < 2 || !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatalf("chunks=%d, reassembly equal=%v", n, bytes.Equal(got.Bytes(), want.Bytes()))
	}
}

func TestRecipientParsingNeverEchoesSecrets(t *testing.T) {
	id, _ := genKey(t)
	_, err := ParseRecipient(id.String())
	if err == nil || strings.Contains(err.Error(), id.String()) || strings.Contains(err.Error(), "AGE-SECRET") {
		t.Fatalf("err = %v", err)
	}
	if _, err := ParseRecipient(fmt.Sprint(id.Recipient())); err != nil {
		t.Fatal(err)
	}
}

func rawTarSeed() []byte {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	put := func(name string, data []byte) {
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Size: int64(len(data))})
		_, _ = tw.Write(data)
	}
	hb, _ := json.Marshal(fakeHeader())
	put(memberHeader, hb)
	put("files/a", []byte("x"))
	m := Manifest{Header: fakeHeader(), RowCounts: map[string]int64{"organizations": 0}, Content: ContentInfo{Files: 1, Bytes: 1},
		Members: []Member{{Name: memberHeader, Size: int64(len(hb)), SHA256: sumBytes(hb)}, {Name: "files/a", Size: 1, SHA256: sumBytes([]byte("x"))}}}
	mb, _ := json.Marshal(m)
	put(memberManifest, mb)
	_ = tw.Close()
	return raw.Bytes()
}

func TestRawSeedIsValid(t *testing.T) {
	w := newWalker(bytes.NewReader(rawTarSeed()))
	if _, err := w.readHeader(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.run(noopHandler{}); err != nil {
		t.Fatal(err)
	}
}

// FuzzWalker feeds arbitrary bytes as the decrypted tar stream: no panics, no hangs.
func FuzzWalker(f *testing.F) {
	seed := rawTarSeed()
	f.Add(seed)
	f.Add(seed[:700])
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, 2048))
	f.Fuzz(func(t *testing.T, data []byte) {
		w := newWalker(bytes.NewReader(data))
		if _, err := w.readHeader(); err != nil {
			return
		}
		_, _ = w.run(noopHandler{})
	})
}

// FuzzManifest feeds arbitrary bytes to the header and manifest decoders.
func FuzzManifest(f *testing.F) {
	hb, _ := json.Marshal(fakeHeader())
	mb, _ := json.Marshal(Manifest{Header: fakeHeader(), RowCounts: map[string]int64{}})
	f.Add(hb)
	f.Add(mb)
	f.Add([]byte(`{"format_version":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeHeader(data)
		_, _ = decodeManifest(data)
		_ = validateRel(string(data))
		_, _ = classify(string(data))
	})
}
