// Package backup implements `librepatch-server backup` and `librepatch-server restore`.
//
// An archive is a tar stream inside an age stream (filippo.io/age). The tar
// members, in order, are:
//
//	header.json          format/app/schema versions, table and column lists, sequences
//	db/tNNNN/NNNNNN.copy PostgreSQL COPY (text format) data of table NNNN, in chunks
//	files/<path>         the content directory (uploaded installers)
//	manifest.json        the header again plus row counts and the sha256 of every other member
//
// The manifest comes last because row counts and hashes are only known once
// the data has been streamed; the header comes first so a restore can create
// the matching schema before it reads any data. The master key and the
// secrets directory are deliberately not part of an archive.
package backup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// FormatVersion is the archive layout version written by this binary.
const FormatVersion = 1

// Names and limits. The limits bound memory and work when an archive is
// hostile: anyone who knows the (public) age recipient can produce a file that
// decrypts, so everything read from an archive is treated as untrusted.
const (
	memberHeader   = "header.json"
	memberManifest = "manifest.json"
	prefixDB       = "db/"
	prefixFiles    = "files/"

	chunkSize        = 8 << 20   // target size of one COPY chunk member
	maxRowBuffer     = 256 << 20 // largest single COPY row we are willing to buffer
	maxHeaderBytes   = 4 << 20
	maxManifestBytes = 64 << 20
	maxMembers       = 200_000
	maxChunkBytes    = 64 << 20
	maxFileBytes     = 16 << 30
	maxTotalBytes    = 8 << 40
	maxTables        = 2_000
	maxColumns       = 1_000
	maxSequences     = 10_000
	maxNameLen       = 1_024
	maxTrailing      = 64 << 10
	maxChunkSeq      = 999_999
)

// Header is written as the first archive member and embedded in the manifest.
type Header struct {
	FormatVersion int        `json:"format_version"`
	AppVersion    string     `json:"app_version"`
	AppCommit     string     `json:"app_commit"`
	SchemaVersion int64      `json:"schema_version"`
	CreatedAt     time.Time  `json:"created_at"`
	Notes         []string   `json:"notes"`
	Tables        []TableDef `json:"tables"`
	Sequences     []SeqDef   `json:"sequences"`
}

// TableDef describes one dumped table. Tables are listed in load order
// (referenced tables before the tables that reference them).
type TableDef struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"` // "table" or "partitioned"
	Columns []string `json:"columns"`
}

// SeqDef is the state of one sequence at backup time.
type SeqDef struct {
	Name      string `json:"name"`
	LastValue int64  `json:"last_value"`
	IsCalled  bool   `json:"is_called"`
}

// Member is one archive member as recorded in the manifest.
type Member struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// ContentInfo summarizes the content-directory files.
type ContentInfo struct {
	Files int   `json:"files"`
	Bytes int64 `json:"bytes"`
}

// Manifest is the last archive member. It authenticates everything before it.
type Manifest struct {
	Header
	RowCounts map[string]int64 `json:"row_counts"`
	Content   ContentInfo      `json:"content"`
	Members   []Member         `json:"members"`
}

// NotMasterKey is recorded in every archive so nobody has to guess.
const NotMasterKey = "The master key (LIBREPATCH_MASTER_KEY_FILE) and the database passwords are NOT part of this backup; " +
	"the database only holds keys sealed with them. Keep the master key that the console showed at first sign-in (or print it with show-master-key)."

// ErrUnknownFormat is returned for an archive whose format version this binary does not understand.
var ErrUnknownFormat = errors.New("unsupported backup format")

func chunkName(table, seq int) string { return fmt.Sprintf("%st%04d/%06d.copy", prefixDB, table, seq) }

var chunkRE = regexp.MustCompile(`^db/t(\d{4})/(\d{6})\.copy$`)

type memberKind int

const (
	kindHeader memberKind = iota
	kindManifest
	kindChunk
	kindFile
)

type memberID struct {
	kind  memberKind
	table int    // kindChunk
	seq   int    // kindChunk
	rel   string // kindFile: path relative to the content directory
}

// classify validates an archive member name and says what it is.
func classify(name string) (memberID, error) {
	switch {
	case name == memberHeader:
		return memberID{kind: kindHeader}, nil
	case name == memberManifest:
		return memberID{kind: kindManifest}, nil
	case strings.HasPrefix(name, prefixDB):
		m := chunkRE.FindStringSubmatch(name)
		if m == nil {
			return memberID{}, fmt.Errorf("unexpected archive member %q", name)
		}
		t, _ := strconv.Atoi(m[1])
		s, _ := strconv.Atoi(m[2])
		if s < 1 {
			return memberID{}, fmt.Errorf("unexpected archive member %q", name)
		}
		return memberID{kind: kindChunk, table: t, seq: s}, nil
	case strings.HasPrefix(name, prefixFiles):
		rel := strings.TrimPrefix(name, prefixFiles)
		if err := validateRel(rel); err != nil {
			return memberID{}, fmt.Errorf("unsafe archive member name %q: %w", name, err)
		}
		return memberID{kind: kindFile, rel: rel}, nil
	}
	return memberID{}, fmt.Errorf("unexpected archive member %q", name)
}

// validateRel accepts only clean, relative, forward-slash paths made of plain
// components. It is the single gate for names that become filesystem paths.
func validateRel(rel string) error {
	if rel == "" || len(rel) > maxNameLen {
		return errors.New("empty or too long")
	}
	if !utf8.ValidString(rel) {
		return errors.New("not valid UTF-8")
	}
	if strings.HasPrefix(rel, "/") {
		return errors.New("absolute path")
	}
	parts := strings.Split(rel, "/")
	if len(parts) > 16 {
		return errors.New("too deep")
	}
	for _, p := range parts {
		switch {
		case p == "" || p == "." || p == "..":
			return errors.New("path traversal or non-canonical path")
		case len(p) > 255:
			return errors.New("component too long")
		case strings.HasPrefix(p, "."):
			return errors.New("hidden component")
		}
		for _, r := range p {
			if r < 0x20 || r == 0x7f || r == '\\' || r == ':' {
				return errors.New("control or reserved character")
			}
		}
	}
	return nil
}

func validIdent(s string) bool {
	return s != "" && len(s) <= 63 && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

// validate checks a header that came from an archive. The names it carries
// are later used in SQL (always quoted) and compared with the live schema.
func (h *Header) validate() error {
	if h.FormatVersion != FormatVersion {
		return fmt.Errorf("%w: format version %d (this binary understands %d)", ErrUnknownFormat, h.FormatVersion, FormatVersion)
	}
	if h.SchemaVersion < 1 {
		return errors.New("backup header: schema version missing")
	}
	if len(h.Tables) == 0 || len(h.Tables) > maxTables {
		return fmt.Errorf("backup header: %d tables", len(h.Tables))
	}
	if len(h.Sequences) > maxSequences {
		return errors.New("backup header: too many sequences")
	}
	seen := map[string]bool{}
	for _, t := range h.Tables {
		if !validIdent(t.Name) || seen[t.Name] {
			return fmt.Errorf("backup header: bad or duplicate table name %q", t.Name)
		}
		seen[t.Name] = true
		if t.Kind != "table" && t.Kind != "partitioned" {
			return fmt.Errorf("backup header: table %q has unknown kind %q", t.Name, t.Kind)
		}
		if len(t.Columns) == 0 || len(t.Columns) > maxColumns {
			return fmt.Errorf("backup header: table %q has %d columns", t.Name, len(t.Columns))
		}
		cols := map[string]bool{}
		for _, c := range t.Columns {
			if !validIdent(c) || cols[c] {
				return fmt.Errorf("backup header: table %q has a bad or duplicate column %q", t.Name, c)
			}
			cols[c] = true
		}
	}
	seen = map[string]bool{}
	for _, s := range h.Sequences {
		if !validIdent(s.Name) || seen[s.Name] {
			return fmt.Errorf("backup header: bad or duplicate sequence name %q", s.Name)
		}
		seen[s.Name] = true
	}
	return nil
}

// formatVersionOf extracts the format version so that a newer archive gets a
// version message instead of a confusing unknown-field error.
func formatVersionOf(b []byte, what string) (int, error) {
	var peek struct {
		FormatVersion int `json:"format_version"`
	}
	if err := json.Unmarshal(b, &peek); err != nil {
		return 0, fmt.Errorf("backup %s is not valid JSON: %w", what, err)
	}
	return peek.FormatVersion, nil
}

func decodeHeader(b []byte) (*Header, error) {
	v, err := formatVersionOf(b, "header")
	if err != nil {
		return nil, err
	}
	if v != FormatVersion {
		return nil, fmt.Errorf("%w: format version %d (this binary understands %d)", ErrUnknownFormat, v, FormatVersion)
	}
	var h Header
	if err := strictJSON(b, &h); err != nil {
		return nil, fmt.Errorf("backup header: %w", err)
	}
	if err := h.validate(); err != nil {
		return nil, err
	}
	return &h, nil
}

func decodeManifest(b []byte) (*Manifest, error) {
	v, err := formatVersionOf(b, "manifest")
	if err != nil {
		return nil, err
	}
	if v != FormatVersion {
		return nil, fmt.Errorf("%w: format version %d (this binary understands %d)", ErrUnknownFormat, v, FormatVersion)
	}
	var m Manifest
	if err := strictJSON(b, &m); err != nil {
		return nil, fmt.Errorf("backup manifest: %w", err)
	}
	if err := m.Header.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func hexSum(sum []byte) string { return hex.EncodeToString(sum) }

func sumBytes(b []byte) string {
	s := sha256.Sum256(b)
	return hexSum(s[:])
}
