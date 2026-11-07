package backup

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/server/audit"
	"github.com/auzring1/librepatch/internal/server/kek"
)

// Errors a caller may want to tell apart.
var (
	// ErrTargetNotEmpty: the database already holds data (or an unmanaged or newer schema).
	ErrTargetNotEmpty = errors.New("restore target is not empty")
	// ErrNewerSchema: the backup was made by a newer server than this binary.
	ErrNewerSchema = errors.New("backup is newer than this server")
	// ErrAuditChainBroken: the restore committed but the audit hash chain does not verify.
	ErrAuditChainBroken = errors.New("audit chain is broken")
)

// RestoreOptions configures Restore.
type RestoreOptions struct {
	// DatabaseURL is the schema-owner connection (the migrator URL).
	DatabaseURL string
	// ContentDir receives the uploaded installers; empty means none can be restored.
	ContentDir string
	Source     Source
	Identities []age.Identity

	// Force and Wipe together allow replacing a database that already holds
	// data; Wipe alone allows rebuilding an empty database whose schema is newer
	// than the backup (or not managed by our migrations).
	Force, Wipe bool
	// SkipContent restores the database only.
	SkipContent bool
	// MasterKey, when set, is checked against the CA keys in the backup, so a
	// restore with the wrong key fails now rather than at the next start.
	MasterKey    []byte
	SkipKEKCheck bool
	Log          *slog.Logger
}

// RestoreResult summarizes a finished restore.
type RestoreResult struct {
	Manifest      *Manifest
	SchemaVersion int64 // after the forward migrations
	AuditEntries  int64 // entries whose hash chain was verified
	ContentFiles  int
	Wiped         bool
}

func (o *RestoreOptions) logger() *slog.Logger {
	if o.Log != nil {
		return o.Log
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Restore loads an archive into an empty database.
//
// The archive is verified first when it can be read twice (a file). The data
// then loads in a single transaction: every member hash is checked against the
// manifest before COMMIT, so a bad archive leaves no rows behind. The schema
// is created beforehand by the embedded migrations, up to the backup's schema
// version, and brought to the newest version afterwards.
func Restore(ctx context.Context, o RestoreOptions) (*RestoreResult, error) {
	log := o.logger()
	if o.DatabaseURL == "" {
		return nil, errors.New("restore: no database URL")
	}
	if o.Source.Repeatable {
		m, err := Verify(ctx, o.Source, o.Identities)
		if err != nil {
			return nil, fmt.Errorf("backup failed verification; the database was not touched: %w", err)
		}
		log.Info("backup verified", "created_at", m.CreatedAt, "schema_version", m.SchemaVersion, "content_files", m.Content.Files)
		if m.Content.Files > 0 && o.ContentDir == "" && !o.SkipContent {
			return nil, errNoContentDir
		}
	}
	rc, err := o.Source.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	dec, err := decrypt(ctxReader{ctx, rc}, o.Identities)
	if err != nil {
		return nil, err
	}
	w := newWalker(dec)
	hdr, err := w.readHeader()
	if err != nil {
		return nil, err
	}
	latest, known, err := migrationVersions()
	if err != nil {
		return nil, err
	}
	if hdr.SchemaVersion > latest {
		return nil, fmt.Errorf("%w: the backup has schema version %d (made by librepatch-server %s) but this binary only knows migrations up to %d; restore with a newer librepatch-server",
			ErrNewerSchema, hdr.SchemaVersion, hdr.AppVersion, latest)
	}
	if !known[hdr.SchemaVersion] {
		return nil, fmt.Errorf("backup schema version %d is not a known migration", hdr.SchemaVersion)
	}
	log.Info("restoring backup", "created_at", hdr.CreatedAt, "app_version", hdr.AppVersion, "schema_version", hdr.SchemaVersion)

	res := &RestoreResult{}
	wiped, err := prepareTarget(ctx, &o, hdr, log)
	if err != nil {
		return nil, err
	}
	res.Wiped = wiped

	manifest, err := loadData(ctx, &o, w, hdr, log)
	if err != nil {
		return nil, err
	}
	res.Manifest = manifest
	res.ContentFiles = manifest.Content.Files

	// The data is committed. Bring the schema forward, then prove the audit chain.
	if err := migrate(ctx, o.DatabaseURL, 0, log); err != nil {
		return res, fmt.Errorf("the data was restored at schema version %d, but migrating forward failed (run `librepatch-server migrate` after fixing it): %w", hdr.SchemaVersion, err)
	}
	res.SchemaVersion = latest
	conn, err := connect(ctx, o.DatabaseURL, "librepatch-restore")
	if err != nil {
		return res, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	if _, err := conn.Exec(ctx, "ANALYZE"); err != nil {
		log.Warn("ANALYZE after restore failed (autovacuum will catch up)", "err", err)
	}
	vr, err := audit.Verify(ctx, dbq.New(conn))
	if err != nil {
		return res, fmt.Errorf("verify audit chain: %w", err)
	}
	res.AuditEntries = vr.Checked
	if vr.BrokenAt != 0 {
		return res, fmt.Errorf("%w: entry %d does not verify (%d entries were fine before it). The restore was committed, but this backup's audit log was already tampered with or damaged; do not trust it, and restore an earlier backup",
			ErrAuditChainBroken, vr.BrokenAt, vr.Checked)
	}
	if err := audit.Log(ctx, conn, audit.Entry{ActorType: audit.ActorSystem, ActorID: "cli", Action: "admin.restore",
		TargetType: "database", Outcome: audit.Success,
		Details: map[string]any{"backup_created_at": hdr.CreatedAt.Format(time.RFC3339), "backup_app_version": hdr.AppVersion,
			"backup_schema_version": hdr.SchemaVersion, "schema_version": latest, "wiped": wiped, "content_files": manifest.Content.Files}}); err != nil {
		log.Warn("could not record the restore in the audit log", "err", err)
	}
	return res, nil
}

var errNoContentDir = errors.New("the backup contains content files but LIBREPATCH_CONTENT_DIR is not set; set it, or pass --skip-content to restore the database only")

// prepareTarget checks the database is fit to receive the backup, wipes it
// if asked to, and creates the schema at the backup's version.
func prepareTarget(ctx context.Context, o *RestoreOptions, hdr *Header, log *slog.Logger) (wiped bool, err error) {
	conn, err := connect(ctx, o.DatabaseURL, "librepatch-restore")
	if err != nil {
		return false, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	st, err := inspectTarget(ctx, conn)
	if err != nil {
		return false, err
	}
	if len(st.rowsIn) > 0 && !(o.Force && o.Wipe) {
		return false, fmt.Errorf("%w: %s already contain data. Restore only goes into an empty database; to REPLACE this database (everything in its public schema is dropped) pass both --force and --wipe",
			ErrTargetNotEmpty, listSome(st.rowsIn))
	}
	switch {
	case o.Wipe:
		if len(st.tables) > 0 || st.hasGoose {
			log.Warn("wiping the public schema of the target database", "tables", len(st.tables), "tables_with_rows", len(st.rowsIn))
			if err := wipeSchema(ctx, conn); err != nil {
				return false, fmt.Errorf("wipe: %w", err)
			}
			wiped = true
			st = &targetState{}
		}
	case st.hasGoose && st.version > hdr.SchemaVersion:
		return false, fmt.Errorf("%w: the (empty) database is already at schema version %d, newer than the backup's %d, and migrations only go forward. Restore into a database that has not been migrated yet (for example recreate it), or pass --wipe to rebuild its schema",
			ErrTargetNotEmpty, st.version, hdr.SchemaVersion)
	case !st.hasGoose && len(st.tables) > 0:
		return false, fmt.Errorf("%w: the database has tables (%s) but no migration history. Use an empty database, or pass --wipe to rebuild the schema",
			ErrTargetNotEmpty, listSome(sortedNames(st.tables)))
	}
	if !st.hasGoose || st.version < hdr.SchemaVersion {
		log.Info("creating schema", "from_version", st.version, "to_version", hdr.SchemaVersion)
		if err := migrate(ctx, o.DatabaseURL, hdr.SchemaVersion, log); err != nil {
			return wiped, err
		}
	}
	return wiped, nil
}

func listSome(names []string) string {
	if len(names) > 4 {
		return strings.Join(names[:4], ", ") + fmt.Sprintf(" and %d more tables", len(names)-4)
	}
	return "table(s) " + strings.Join(names, ", ")
}

func wipeSchema(ctx context.Context, conn *pgx.Conn) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	for _, s := range []string{"DROP SCHEMA public CASCADE", "CREATE SCHEMA public", "GRANT USAGE ON SCHEMA public TO PUBLIC"} {
		if _, err := tx.Exec(ctx, s); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

type copyResult struct {
	rows int64
	err  error
}

type activeCopy struct {
	table int
	pw    *io.PipeWriter
	done  chan copyResult
}

var errAborted = errors.New("restore aborted")

// restoreHandler feeds archive members into the open transaction.
type restoreHandler struct {
	ctx         context.Context
	pgc         *pgconn.PgConn
	hdr         *Header
	cp          *activeCopy
	loaded      map[string]int64
	skipContent bool
	root        *os.Root
	stage       string
	staged      []string
}

func (h *restoreHandler) OnChunk(table int, r io.Reader) error {
	if h.cp == nil {
		t := h.hdr.Tables[table]
		pr, pw := io.Pipe()
		cp := &activeCopy{table: table, pw: pw, done: make(chan copyResult, 1)}
		sqlText := "COPY " + qident("public", t.Name) + " (" + quoteCols(t.Columns) + ") FROM STDIN"
		go func() {
			tag, err := h.pgc.CopyFrom(h.ctx, pr, sqlText)
			if err != nil {
				_ = pr.CloseWithError(err)
			} else {
				_ = pr.Close()
			}
			cp.done <- copyResult{rows: tag.RowsAffected(), err: err}
		}()
		h.cp = cp
	}
	if _, err := io.Copy(h.cp.pw, r); err != nil {
		// A write error means the database refused the data: report its reason.
		cp := h.cp
		h.cp = nil
		_ = cp.pw.CloseWithError(errAborted)
		if res := <-cp.done; res.err != nil {
			return fmt.Errorf("loading table %s: %w", h.hdr.Tables[table].Name, res.err)
		}
		return err
	}
	return nil
}

func (h *restoreHandler) OnTableEnd(table int) error {
	cp := h.cp
	if cp == nil {
		return nil
	}
	h.cp = nil
	_ = cp.pw.Close()
	res := <-cp.done
	name := h.hdr.Tables[table].Name
	if res.err != nil {
		return fmt.Errorf("loading table %s: %w", name, res.err)
	}
	h.loaded[name] = res.rows
	return nil
}

// abort stops a running COPY so that the connection is free for ROLLBACK.
func (h *restoreHandler) abort() {
	if cp := h.cp; cp != nil {
		h.cp = nil
		_ = cp.pw.CloseWithError(errAborted)
		<-cp.done
	}
}

func (h *restoreHandler) OnFile(rel string, size int64, r io.Reader) error {
	if h.skipContent {
		return nil
	}
	if h.root == nil {
		return errNoContentDir
	}
	dst := path.Join(h.stage, rel)
	if err := h.root.MkdirAll(path.Dir(dst), 0o700); err != nil {
		return err
	}
	f, err := h.root.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, r)
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("restoring %s: %w", rel, err)
	}
	h.staged = append(h.staged, rel)
	return nil
}

// loadData runs the single restore transaction and returns the verified manifest.
func loadData(ctx context.Context, o *RestoreOptions, w *walker, hdr *Header, log *slog.Logger) (*Manifest, error) {
	conn, err := connect(ctx, o.DatabaseURL, "librepatch-restore")
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '30s'"); err != nil {
		return nil, err
	}

	target, err := discoverTables(ctx, tx)
	if err != nil {
		return nil, err
	}
	var lock []string
	for _, t := range target {
		lock = append(lock, qident("public", t.name))
	}
	if len(lock) == 0 {
		return nil, errors.New("the database has no tables after migrating; cannot restore")
	}
	// Writers (a running server) block here instead of racing the load.
	// Table and sequence names come from the catalog and are quoted with pgx.Identifier; identifiers cannot be bind parameters.
	// nosemgrep: no-sql-string-building
	if _, err := tx.Exec(ctx, "LOCK TABLE "+strings.Join(lock, ", ")+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		return nil, fmt.Errorf("lock tables (is the server still running? stop it first): %w", err)
	}
	if rows, err := tablesWithRows(ctx, tx, target); err != nil {
		return nil, err
	} else if len(rows) > 0 {
		return nil, fmt.Errorf("%w: %s already contain data", ErrTargetNotEmpty, listSome(rows))
	}
	seqs, err := discoverSequences(ctx, tx)
	if err != nil {
		return nil, err
	}
	if err := matchSchema(hdr, target, seqs); err != nil {
		return nil, err
	}
	// Triggers must not fire on restored rows (they would rewrite or reject
	// data that is already final); foreign keys are system triggers and stay on.
	for _, t := range hdr.Tables {
		// Table and sequence names come from the catalog and are quoted with pgx.Identifier; identifiers cannot be bind parameters.
		// nosemgrep: no-sql-string-building
		if _, err := tx.Exec(ctx, "ALTER TABLE "+qident("public", t.Name)+" DISABLE TRIGGER USER"); err != nil {
			return nil, err
		}
	}

	h := &restoreHandler{ctx: ctx, pgc: tx.Conn().PgConn(), hdr: hdr, loaded: map[string]int64{}, skipContent: o.SkipContent}
	var placed []string
	var root *os.Root
	cleanup := func() {
		if root == nil {
			return
		}
		for _, p := range placed {
			_ = root.Remove(p)
		}
		_ = root.RemoveAll(h.stage)
		_ = root.Close()
	}
	if o.ContentDir != "" && !o.SkipContent {
		if err := os.MkdirAll(o.ContentDir, 0o700); err != nil {
			return nil, err
		}
		if root, err = os.OpenRoot(o.ContentDir); err != nil {
			return nil, fmt.Errorf("content directory: %w", err)
		}
		var rnd [8]byte
		_, _ = rand.Read(rnd[:])
		h.root, h.stage = root, ".restore-"+hex.EncodeToString(rnd[:])
	}
	committed := false
	defer func() {
		if !committed {
			h.abort()
			cleanup()
		}
	}()

	manifest, err := w.run(h)
	if err != nil {
		h.abort()
		return nil, err
	}
	for _, t := range hdr.Tables {
		if got, want := h.loaded[t.Name], manifest.RowCounts[t.Name]; got != want {
			return nil, fmt.Errorf("table %s: the database accepted %d rows but the manifest says %d", t.Name, got, want)
		}
	}
	for _, t := range hdr.Tables {
		// Table and sequence names come from the catalog and are quoted with pgx.Identifier; identifiers cannot be bind parameters.
		// nosemgrep: no-sql-string-building
		if _, err := tx.Exec(ctx, "ALTER TABLE "+qident("public", t.Name)+" ENABLE TRIGGER USER"); err != nil {
			return nil, err
		}
	}
	for _, s := range hdr.Sequences {
		if _, err := tx.Exec(ctx, "SELECT setval($1::regclass, $2, $3)", qident("public", s.Name), s.LastValue, s.IsCalled); err != nil {
			return nil, fmt.Errorf("reset sequence %s: %w", s.Name, err)
		}
	}
	if len(o.MasterKey) > 0 && !o.SkipKEKCheck {
		if err := checkMasterKey(ctx, tx, o.MasterKey); err != nil {
			return nil, err
		}
	}
	if root != nil {
		for _, rel := range h.staged {
			if err := root.MkdirAll(path.Dir(rel), 0o700); err != nil {
				return nil, err
			}
			_, statErr := root.Lstat(rel)
			if err := root.Rename(path.Join(h.stage, rel), rel); err != nil {
				return nil, fmt.Errorf("place %s: %w", rel, err)
			}
			if statErr != nil { // newly created: remove again if the commit fails
				placed = append(placed, rel)
			}
		}
		_ = root.RemoveAll(h.stage)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	committed = true
	if root != nil {
		_ = root.Close()
	}
	log.Info("data restored", "tables", len(hdr.Tables), "content_files", len(h.staged))
	return manifest, nil
}

// checkMasterKey tries to open the KEK-sealed CA keys stored in the backup.
func checkMasterKey(ctx context.Context, q querier, key []byte) error {
	s, err := kek.New(key)
	if err != nil {
		return err
	}
	rows, err := q.Query(ctx, `SELECT kind, key_enc FROM pki_material WHERE retired_at IS NULL AND key_protection = 'kek' AND kind IN ('issuing', 'job_signing')`)
	if err != nil {
		return err
	}
	type sealed struct {
		kind string
		enc  []byte
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (sealed, error) {
		var v sealed
		return v, r.Scan(&v.kind, &v.enc)
	})
	if err != nil {
		return err
	}
	for _, v := range list {
		purpose := kek.PurposeIssuingKey
		if v.kind == "job_signing" {
			purpose = kek.PurposeJobSigningKey
		}
		if _, err := s.Open(purpose, v.enc); err != nil {
			return fmt.Errorf("the master key (LIBREPATCH_MASTER_KEY_FILE) cannot open the %s key stored in this backup: %w. Restore with the master key that was in use when the backup was made (store it with set-master-key before restoring), or pass --skip-kek-check", v.kind, err)
		}
	}
	return nil
}
