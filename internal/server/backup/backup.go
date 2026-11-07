package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/shared/version"
)

// BackupOptions configures Backup.
type BackupOptions struct {
	// DatabaseURL is the schema-owner connection (the migrator URL).
	DatabaseURL string
	// ContentDir is the uploaded-installer directory; empty means none.
	ContentDir string
	// Out receives the age-encrypted archive.
	Out io.Writer
	// Recipients encrypt the archive. At least one is required.
	Recipients []age.Recipient
	Log        *slog.Logger
	Now        func() time.Time
}

func (o *BackupOptions) logger() *slog.Logger {
	if o.Log != nil {
		return o.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// archiveWriter writes tar members and remembers their hashes for the manifest.
type archiveWriter struct {
	tw      *tar.Writer
	mod     time.Time
	members []Member
}

func (a *archiveWriter) begin(name string, size int64) error {
	if len(a.members) >= maxMembers-1 {
		return fmt.Errorf("too many archive members (limit %d); this backup format cannot hold more", maxMembers)
	}
	return a.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Size: size, Mode: 0o600, ModTime: a.mod})
}

func (a *archiveWriter) putBytes(name string, data []byte) error {
	if err := a.begin(name, int64(len(data))); err != nil {
		return err
	}
	if _, err := a.tw.Write(data); err != nil {
		return err
	}
	a.members = append(a.members, Member{Name: name, Size: int64(len(data)), SHA256: sumBytes(data)})
	return nil
}

// putStream copies exactly size bytes from r.
func (a *archiveWriter) putStream(name string, size int64, r io.Reader) error {
	if err := a.begin(name, size); err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.CopyN(io.MultiWriter(a.tw, h), r, size)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%s shrank while it was being read (%d of %d bytes)", name, n, size)
		}
		return err
	}
	a.members = append(a.members, Member{Name: name, Size: size, SHA256: hexSum(h.Sum(nil))})
	return nil
}

// chunker turns the COPY output of one table into bounded tar members. COPY
// text escapes newlines inside values, so cutting after a raw newline never
// splits a row. Memory use is bounded by chunkSize (or one row, capped).
type chunker struct {
	aw    *archiveWriter
	table int
	seq   int
	buf   []byte
	rows  int64
}

func (c *chunker) Write(p []byte) (int, error) {
	c.rows += int64(bytes.Count(p, []byte{'\n'}))
	c.buf = append(c.buf, p...)
	if len(c.buf) >= chunkSize {
		i := bytes.LastIndexByte(c.buf, '\n')
		switch {
		case i >= 0:
			if err := c.flush(c.buf[:i+1]); err != nil {
				return 0, err
			}
			n := copy(c.buf, c.buf[i+1:])
			c.buf = c.buf[:n]
		case len(c.buf) > maxRowBuffer:
			return 0, errors.New("a single table row is larger than 256 MiB; refusing to buffer it")
		}
	}
	return len(p), nil
}

func (c *chunker) flush(data []byte) error {
	c.seq++
	if c.seq > maxChunkSeq {
		return errors.New("table is too large for this backup format")
	}
	return c.aw.putBytes(chunkName(c.table, c.seq), data)
}

func (c *chunker) close() error {
	if len(c.buf) == 0 {
		return nil
	}
	if c.buf[len(c.buf)-1] != '\n' {
		return errors.New("COPY output did not end at a row boundary")
	}
	err := c.flush(c.buf)
	c.buf = nil
	return err
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Backup writes an encrypted archive of the database and content directory to o.Out.
//
// All tables are read inside one REPEATABLE READ READ ONLY transaction, so the
// archive is a consistent snapshot even while the server keeps running. The
// content files are read afterwards: they are written once and addressed by
// hash, so a file added in between is merely extra and a referenced file always exists.
func Backup(ctx context.Context, o BackupOptions) (*Manifest, error) {
	if len(o.Recipients) == 0 {
		return nil, ErrNoRecipient
	}
	if o.Out == nil {
		return nil, errors.New("backup: no output")
	}
	log := o.logger()
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	created := now().UTC().Truncate(time.Second)

	conn, err := connect(ctx, o.DatabaseURL, "librepatch-backup")
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()

	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	has, schemaVer, err := schemaVersion(ctx, tx)
	if err != nil {
		return nil, err
	}
	if !has || schemaVer < 1 {
		return nil, errors.New("the database has no migration history (is this a " + brand.Name + " database? run `" + brand.Slug + "-server migrate` first)")
	}
	tables, err := discoverTables(ctx, tx)
	if err != nil {
		return nil, err
	}
	if tables, err = orderTables(ctx, tx, tables); err != nil {
		return nil, err
	}
	seqNames, err := discoverSequences(ctx, tx)
	if err != nil {
		return nil, err
	}
	seqs, err := readSequences(ctx, tx, seqNames)
	if err != nil {
		return nil, err
	}

	hdr := Header{
		FormatVersion: FormatVersion,
		AppVersion:    version.Version,
		AppCommit:     version.Commit,
		SchemaVersion: schemaVer,
		CreatedAt:     created,
		Notes: []string{
			NotMasterKey,
			"Table data is PostgreSQL COPY text format, loaded with COPY FROM; files/ is the content directory.",
			"Restore with this or a newer librepatch-server; the schema is rebuilt from the embedded migrations.",
		},
		Sequences: seqs,
	}
	for _, t := range tables {
		hdr.Tables = append(hdr.Tables, TableDef{Name: t.name, Kind: t.kind, Columns: t.cols})
	}

	cw := &countWriter{w: o.Out}
	enc, err := age.Encrypt(cw, o.Recipients...)
	if err != nil {
		return nil, fmt.Errorf("start encryption: %w", err)
	}
	aw := &archiveWriter{tw: tar.NewWriter(enc), mod: created}

	rawHdr, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	if err := aw.putBytes(memberHeader, rawHdr); err != nil {
		return nil, err
	}
	rowCounts := make(map[string]int64, len(tables))
	pgc := tx.Conn().PgConn()
	for i, t := range tables {
		only := ""
		if t.kind == "table" {
			only = "ONLY " // plain tables: do not also pick up inheritance children, they are dumped on their own
		}
		sqlText := "COPY (SELECT " + quoteCols(t.cols) + " FROM " + only + qident("public", t.name) + ") TO STDOUT"
		ch := &chunker{aw: aw, table: i}
		tag, err := pgc.CopyTo(ctx, ch, sqlText)
		if err != nil {
			return nil, fmt.Errorf("copy table %s: %w", t.name, err)
		}
		if err := ch.close(); err != nil {
			return nil, fmt.Errorf("copy table %s: %w", t.name, err)
		}
		if tag.RowsAffected() != ch.rows {
			return nil, fmt.Errorf("copy table %s: server reported %d rows but %d were written", t.name, tag.RowsAffected(), ch.rows)
		}
		rowCounts[t.name] = ch.rows
		log.Info("table backed up", "table", t.name, "rows", ch.rows)
	}
	// The snapshot is no longer needed; do not hold back vacuum while files stream.
	if err := tx.Rollback(ctx); err != nil {
		return nil, err
	}

	var content ContentInfo
	if o.ContentDir != "" {
		if content, err = addContent(ctx, aw, o.ContentDir, log); err != nil {
			return nil, err
		}
	} else {
		log.Info("no content directory configured; backing up the database only")
	}

	m := &Manifest{Header: hdr, RowCounts: rowCounts, Content: content, Members: aw.members}
	rawM, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return nil, err
	}
	if len(rawM) > maxManifestBytes {
		return nil, errors.New("manifest too large")
	}
	if err := aw.begin(memberManifest, int64(len(rawM))); err != nil {
		return nil, err
	}
	if _, err := aw.tw.Write(rawM); err != nil {
		return nil, err
	}
	if err := aw.tw.Close(); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}

	// Record the export in the audit log (best effort: a backup must not fail
	// because the audit write did). The snapshot above does not contain this entry.
	if err := audit.Log(ctx, conn, audit.Entry{ActorType: audit.ActorSystem, ActorID: "cli", Action: "admin.backup",
		TargetType: "database", Outcome: audit.Success,
		Details: map[string]any{"schema_version": schemaVer, "tables": len(tables), "content_files": content.Files, "bytes": cw.n}}); err != nil {
		log.Warn("could not record the backup in the audit log", "err", err)
	}
	log.Info("backup complete", "bytes", cw.n, "tables", len(tables), "content_files", content.Files)
	return m, nil
}

func quoteCols(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = pgx.Identifier{c}.Sanitize()
	}
	return strings.Join(q, ", ")
}

// addContent streams every regular file below dir. Symlinks and dot-files
// (the store's upload temp files) are skipped; the walk never leaves dir.
func addContent(ctx context.Context, aw *archiveWriter, dir string, log *slog.Logger) (ContentInfo, error) {
	var info ContentInfo
	root, err := os.OpenRoot(dir)
	if err != nil {
		return info, fmt.Errorf("content directory: %w", err)
	}
	defer func() { _ = root.Close() }()
	fsys := root.FS()
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if p == "." {
			return nil
		}
		if strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			log.Warn("skipping content entry that is not a regular file", "path", p, "type", d.Type().String())
			return nil
		}
		if err := validateRel(p); err != nil {
			return fmt.Errorf("content file %q cannot be backed up: %w", p, err)
		}
		f, err := fsys.Open(p)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		st, err := f.Stat()
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() {
			return nil
		}
		if st.Size() > maxFileBytes {
			return fmt.Errorf("content file %q is larger than the supported %d bytes", p, int64(maxFileBytes))
		}
		if err := aw.putStream(prefixFiles+p, st.Size(), f); err != nil {
			return err
		}
		info.Files++
		info.Bytes += st.Size()
		return nil
	})
	if err != nil {
		return info, fmt.Errorf("content directory: %w", err)
	}
	log.Info("content backed up", "files", info.Files, "bytes", info.Bytes)
	return info, nil
}
