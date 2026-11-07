package wingetindex

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/auzring1/librepatch/internal/shared/text"
)

// DefaultURL is where Microsoft publishes the index the winget client uses.
const DefaultURL = "https://cdn.winget.microsoft.com/cache/source2.msix"

const (
	maxDownload = 64 << 20
	// RefreshEvery is how old the stored index may get before the server fetches it again.
	RefreshEvery = 24 * time.Hour
	checkEvery   = 6 * time.Hour
)

// Status is what the console shows about the index.
type Status struct {
	Enabled       bool       `json:"enabled"`
	URL           string     `json:"url"`
	PackageCount  int        `json:"package_count"`
	FetchedAt     *time.Time `json:"fetched_at"`
	SourceUpdated *time.Time `json:"source_updated_at"`
	CheckedAt     *time.Time `json:"checked_at"`
	Error         string     `json:"error,omitempty"`
}

// Service downloads, stores and serves the index.
type Service struct {
	Pool   *pgxpool.Pool
	URL    string // "" = DefaultURL
	Client *http.Client
	Log    *slog.Logger
	Now    func() time.Time
	// AllowHTTP permits a plain-http URL (tests only).
	AllowHTTP bool

	cur atomic.Pointer[Matcher]
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) url() string {
	if s.URL != "" {
		return s.URL
	}
	return DefaultURL
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 3 * time.Minute, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 || (r.URL.Scheme != "https" && !s.AllowHTTP) {
			return errors.New("redirect refused")
		}
		return nil
	}}
}

// Matcher is the current index, or nil when none has been loaded yet.
func (s *Service) Matcher() *Matcher {
	if s == nil {
		return nil
	}
	return s.cur.Load()
}

// Load reads the stored index (if any) into memory. Call once at start-up.
func (s *Service) Load(ctx context.Context) error {
	var data []byte
	err := s.Pool.QueryRow(ctx, `SELECT data FROM winget_index WHERE id = 1 AND data IS NOT NULL`).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	snap, err := ParseMSIX(data)
	if err != nil {
		return fmt.Errorf("stored winget index: %w", err)
	}
	s.cur.Store(NewMatcher(snap))
	return nil
}

// Status reports the stored index.
func (s *Service) Status(ctx context.Context) (Status, error) {
	st := Status{Enabled: true, URL: s.url()}
	var fetched, modified, checked *time.Time
	err := s.Pool.QueryRow(ctx, `SELECT package_count, fetched_at, source_modified, checked_at, last_error FROM winget_index WHERE id = 1`).
		Scan(&st.PackageCount, &fetched, &modified, &checked, &st.Error)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return st, err
	}
	st.FetchedAt, st.SourceUpdated, st.CheckedAt = fetched, modified, checked
	return st, nil
}

// Refresh downloads the index when the stored one is older than RefreshEvery (or always, with force), validates it and
// stores it. It returns whether a new index was stored.
func (s *Service) Refresh(ctx context.Context, force bool) (bool, error) {
	var etag, lastMod string
	var fetched *time.Time
	err := s.Pool.QueryRow(ctx, `SELECT etag, last_modified, fetched_at FROM winget_index WHERE id = 1`).Scan(&etag, &lastMod, &fetched)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	if !force && fetched != nil && s.now().Sub(*fetched) < RefreshEvery && s.cur.Load() != nil {
		return false, nil
	}
	body, newTag, newMod, notModified, ferr := s.fetch(ctx, etag, lastMod)
	if ferr != nil {
		s.record(ctx, ferr.Error())
		return false, ferr
	}
	if notModified {
		_, _ = s.Pool.Exec(ctx, `UPDATE winget_index SET fetched_at = $1, checked_at = $1, last_error = '' WHERE id = 1`, s.now())
		return false, nil
	}
	snap, perr := ParseMSIX(body)
	if perr != nil {
		s.record(ctx, perr.Error())
		return false, perr
	}
	now := s.now()
	var modified *time.Time
	if !snap.Modified.IsZero() {
		modified = &snap.Modified
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO winget_index (id, data, fetched_at, source_modified, etag, last_modified, package_count, checked_at, last_error)
VALUES (1, $1, $2, $3, $4, $5, $6, $2, '')
ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, fetched_at = EXCLUDED.fetched_at, source_modified = EXCLUDED.source_modified,
  etag = EXCLUDED.etag, last_modified = EXCLUDED.last_modified, package_count = EXCLUDED.package_count, checked_at = EXCLUDED.checked_at, last_error = ''`,
		body, now, modified, newTag, newMod, len(snap.Packages))
	if err != nil {
		return false, err
	}
	s.cur.Store(NewMatcher(snap))
	s.log().Info("winget index updated", "packages", len(snap.Packages), "bytes", len(body))
	return true, nil
}

// record keeps the reason of a failed attempt for the console.
func (s *Service) record(ctx context.Context, msg string) {
	msg = text.Truncate(msg, 300)
	_, _ = s.Pool.Exec(ctx, `INSERT INTO winget_index (id, checked_at, last_error) VALUES (1, $1, $2)
ON CONFLICT (id) DO UPDATE SET checked_at = EXCLUDED.checked_at, last_error = EXCLUDED.last_error`, s.now(), msg)
	s.log().Warn("winget index refresh failed", "err", msg)
}

func (s *Service) fetch(ctx context.Context, etag, lastMod string) (body []byte, newTag, newMod string, notModified bool, err error) {
	u, perr := url.Parse(s.url())
	if perr != nil || (u.Scheme != "https" && !(s.AllowHTTP && u.Scheme == "http")) || u.Host == "" {
		return nil, "", "", false, errors.New("the winget index address must be an https URL")
	}
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if rerr != nil {
		return nil, "", "", false, rerr
	}
	req.Header.Set("User-Agent", "librepatch-winget-index")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	} else if lastMod != "" {
		req.Header.Set("If-Modified-Since", lastMod)
	}
	resp, derr := s.client().Do(req)
	if derr != nil {
		return nil, "", "", false, fmt.Errorf("could not download the winget index: %w", derr)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, etag, lastMod, true, nil
	case resp.StatusCode != http.StatusOK:
		return nil, "", "", false, fmt.Errorf("the winget index server answered %s", resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, "", "", false, fmt.Errorf("could not download the winget index: %w", err)
	}
	if len(body) > maxDownload {
		return nil, "", "", false, errors.New("the winget index download is unreasonably large")
	}
	return body, strings.TrimSpace(resp.Header.Get("ETag")), strings.TrimSpace(resp.Header.Get("Last-Modified")), false, nil
}

// Run loads the stored index, then keeps it fresh until ctx ends. The first download waits a little so start-up stays
// quiet; a failure is recorded and retried at the next check.
func (s *Service) Run(ctx context.Context) {
	if err := s.Load(ctx); err != nil {
		s.log().Error("winget index load", "err", err)
	}
	wait := 30 * time.Second
	if s.cur.Load() != nil {
		wait = time.Minute
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		rctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		_, _ = s.Refresh(rctx, false)
		cancel()
		wait = checkEvery
	}
}

// Use installs a parsed index without downloading it (tests, and tools that already hold one).
func (s *Service) Use(snap *Snapshot) { s.cur.Store(NewMatcher(snap)) }
