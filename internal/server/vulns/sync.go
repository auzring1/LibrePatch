package vulns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/safehttp"
	"github.com/auzring1/librepatch/internal/server/settings"
)

// How often and how much the feeds are asked for.
const (
	kevEvery        = 12 * time.Hour
	nvdEvery        = 23 * time.Hour
	maxPages        = 50   // per product and run: 100,000 CVEs
	maxRequests     = 60   // per run, over all products; the rest waits for the next run
	pageSize        = 2000 // the NVD maximum
	incrementalDays = 100  // the NVD allows a modified-since window of 120 days
	keyDelay        = 800 * time.Millisecond
	noKeyDelay      = 6500 * time.Millisecond
)

// ErrOff is returned when the lookup is not turned on.
var ErrOff = errors.New("vulns: vulnerability lookup is turned off")

// Service downloads the feeds and keeps the tables current.
type Service struct {
	Store    *Store
	Settings *settings.Service
	Log      *slog.Logger
	// HTTP replaces the default client (tests). Sleep replaces the pause between NVD requests (tests).
	HTTP  *http.Client
	Sleep func(ctx context.Context, d time.Duration)
	Now   func() time.Time

	mu      sync.Mutex
	running bool
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Service) pause(ctx context.Context, d time.Duration) {
	if s.Sleep != nil {
		s.Sleep(ctx, d)
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// Report says what a run did.
type Report struct {
	KEV      string   `json:"kev"` // downloaded | unchanged | skipped | failed
	KEVItems int      `json:"kev_items"`
	Products int      `json:"products"` // NVD products refreshed
	Pending  int      `json:"pending"`  // products left for the next run
	CVEs     int      `json:"cves"`     // CVEs stored or updated
	Requests int      `json:"requests"`
	Errors   []string `json:"errors"`
}

type config struct {
	enabled bool
	kevURL  string
	nvdURL  string
	apiKey  string
}

func (s *Service) config(ctx context.Context, org uuid.UUID) config {
	v := s.Settings.Values(ctx, org, "vulnerabilities")
	key, _ := s.Settings.Secret(ctx, org, "vulnerabilities", "nvd_api_key")
	return config{enabled: v.Bool("enabled"), kevURL: v.Str("kev_url"), nvdURL: v.Str("nvd_url"), apiKey: key}
}

// Tick runs a sync when the lookup is on (the server's timer calls it every so often; the feeds themselves are only asked
// when they are due).
func (s *Service) Tick(ctx context.Context) {
	org, err := s.Settings.Org(ctx)
	if err != nil {
		return
	}
	if !s.config(ctx, org).enabled {
		return
	}
	if _, err := s.Sync(ctx, org, false); err != nil && !errors.Is(err, ErrOff) {
		s.log().Error("vulnerability sync", "err", err)
	}
}

// Sync downloads what is due: the CISA list and, for each product the fleet has, what the NVD says about it. force asks
// for everything now. One sync runs at a time.
func (s *Service) Sync(ctx context.Context, org uuid.UUID, force bool) (*Report, error) {
	cfg := s.config(ctx, org)
	if !cfg.enabled {
		return nil, ErrOff
	}
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil, fmt.Errorf("%w: a sync is already running", ErrConflict)
	}
	s.running = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.running = false; s.mu.Unlock() }()

	rep := &Report{KEV: "skipped", Errors: []string{}}
	if err := s.Store.EnsureBuiltinProducts(ctx, org); err != nil {
		return nil, err
	}
	feeds, err := s.Store.Feeds(ctx)
	if err != nil {
		return nil, err
	}
	state := map[string]Feed{}
	for _, f := range feeds {
		state[f.Feed] = f
	}
	due := func(name string, every time.Duration) (Feed, bool) {
		f, ok := state[name]
		return f, force || !ok || f.LastOK == nil || s.now().Sub(*f.LastOK) >= every
	}

	if f, ok := due("kev", kevEvery); ok {
		s.syncKEV(ctx, cfg, f, rep)
	}

	pairs, err := s.Store.FleetPairs(ctx, org)
	if err != nil {
		return rep, err
	}
	for _, p := range pairs {
		name := "nvd:" + p.Vendor + ":" + p.Product
		f, ok := due(name, nvdEvery)
		if !ok {
			continue
		}
		if rep.Requests >= maxRequests || ctx.Err() != nil {
			rep.Pending++
			continue
		}
		if err := s.syncProduct(ctx, cfg, p, f, rep); err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %v", name, err))
			_ = s.Store.RecordFeed(ctx, name, false, err.Error(), "", 0)
			if errors.Is(err, errRateLimited) {
				rep.Pending++
				break // the rest waits: asking more would only be refused
			}
			continue
		}
		rep.Products++
	}
	return rep, nil
}

func (s *Service) syncKEV(ctx context.Context, cfg config, f Feed, rep *Report) {
	body, tag, notModified, err := s.get(ctx, cfg.kevURL, f.ETag, "")
	if err != nil {
		rep.KEV = "failed"
		rep.Errors = append(rep.Errors, "CISA list: "+err.Error())
		_ = s.Store.RecordFeed(ctx, "kev", false, err.Error(), "", 0)
		return
	}
	if notModified {
		rep.KEV = "unchanged"
		_ = s.Store.RecordFeed(ctx, "kev", true, "", f.ETag, f.Items)
		return
	}
	entries, err := ParseKEV(body)
	if err == nil {
		err = s.Store.ApplyKEV(ctx, entries)
	}
	if err != nil {
		rep.KEV = "failed"
		rep.Errors = append(rep.Errors, "CISA list: "+err.Error())
		_ = s.Store.RecordFeed(ctx, "kev", false, err.Error(), "", 0)
		return
	}
	rep.KEV, rep.KEVItems = "downloaded", len(entries)
	_ = s.Store.RecordFeed(ctx, "kev", true, "", tag, len(entries))
}

var errRateLimited = errors.New("the NVD refused the request (rate limit); the rest waits for the next run")

// cpeEscape writes a CPE component the way the NVD's search expects: every character that is not a letter, a digit or one of
// "_-." escaped with a backslash.
func cpeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('\\')
		b.WriteRune(r)
	}
	return b.String()
}

// nvdTimeParam is the format the NVD's date parameters take.
func nvdTimeParam(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000") }

func (s *Service) syncProduct(ctx context.Context, cfg config, p Pair, f Feed, rep *Report) error {
	base, err := url.Parse(cfg.nvdURL)
	if err != nil {
		return err
	}
	tracked := Tracked{{p.Vendor, p.Product}: true}
	scope := [][2]string{{p.Vendor, p.Product}}
	// What changed since the last full or incremental run, when that was recent enough; everything otherwise.
	var since *time.Time
	if f.LastOK != nil && s.now().Sub(*f.LastOK) < incrementalDays*24*time.Hour {
		t := f.LastOK.Add(-time.Hour)
		since = &t
	}
	delay := noKeyDelay
	if cfg.apiKey != "" {
		delay = keyDelay
	}
	stored := 0
	for page, start := 0, 0; page < maxPages; page++ {
		if rep.Requests >= maxRequests {
			return fmt.Errorf("stopped after %d requests; it continues on the next run", maxRequests)
		}
		if rep.Requests > 0 {
			s.pause(ctx, delay)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		q := url.Values{}
		q.Set("virtualMatchString", "cpe:2.3:"+p.Part+":"+cpeEscape(p.Vendor)+":"+cpeEscape(p.Product))
		q.Set("resultsPerPage", strconv.Itoa(pageSize))
		q.Set("startIndex", strconv.Itoa(start))
		if since != nil {
			q.Set("lastModStartDate", nvdTimeParam(*since))
			q.Set("lastModEndDate", nvdTimeParam(s.now()))
		}
		u := *base
		u.RawQuery = q.Encode()
		rep.Requests++
		body, _, _, err := s.get(ctx, u.String(), "", cfg.apiKey)
		if err != nil {
			return err
		}
		pg, err := ParseNVD(body, tracked)
		if err != nil {
			return err
		}
		if err := s.Store.UpsertCVEs(ctx, pg.CVEs, scope); err != nil {
			return err
		}
		stored += len(pg.CVEs)
		rep.CVEs += len(pg.CVEs)
		// The next page starts where this one ended (the answer says how many it held, which counts entries we skipped too).
		step := pg.PerPage
		if step <= 0 {
			step = len(pg.CVEs)
		}
		start = pg.StartIndex + step
		if step == 0 || start >= pg.TotalResults {
			return s.Store.RecordFeed(ctx, "nvd:"+p.Vendor+":"+p.Product, true, "", "", stored)
		}
	}
	return fmt.Errorf("more than %d pages; it continues on the next run", maxPages)
}

// get downloads one address. A 304 to a stored ETag reports notModified; 403 and 429 from the NVD mean "slow down".
func (s *Service) get(ctx context.Context, link, etag, apiKey string) (body []byte, newTag string, notModified bool, err error) {
	c := s.HTTP
	if c == nil {
		c = safehttp.NewClientTimeout(5 * time.Minute)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return nil, "", false, err
	}
	req.Header.Set("User-Agent", "librepatch-vulnerability-sync")
	req.Header.Set("Accept", "application/json")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return nil, etag, true, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden:
		return nil, "", false, errRateLimited
	case resp.StatusCode != http.StatusOK:
		return nil, "", false, fmt.Errorf("the server answered %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxFeedBytes+1))
	if err != nil {
		return nil, "", false, err
	}
	if len(b) > MaxFeedBytes {
		return nil, "", false, fmt.Errorf("the answer is larger than %d bytes", MaxFeedBytes)
	}
	tag := resp.Header.Get("ETag")
	if len(tag) > 200 {
		tag = ""
	}
	return b, tag, false, nil
}

// Status is the state of the lookup: whether it is on, how much data there is and what each feed last did.
type Status struct {
	Enabled  bool       `json:"enabled"`
	Counts   Counts     `json:"counts"`
	Feeds    []Feed     `json:"feeds"`
	Tracked  int        `json:"tracked_products"` // CPE products the fleet has
	KEVAt    *time.Time `json:"kev_updated_at"`
	NVDAt    *time.Time `json:"nvd_updated_at"` // the oldest successful refresh of a product the fleet has
	Problems int        `json:"problems"`       // feeds whose last attempt failed
}

// Status reads the state.
func (s *Service) Status(ctx context.Context, org uuid.UUID) (*Status, error) {
	st := &Status{Enabled: s.config(ctx, org).enabled}
	var err error
	if st.Counts, err = s.Store.Counts(ctx); err != nil {
		return nil, err
	}
	if st.Feeds, err = s.Store.Feeds(ctx); err != nil {
		return nil, err
	}
	if st.Feeds == nil {
		st.Feeds = []Feed{}
	}
	pairs, err := s.Store.FleetPairs(ctx, org)
	if err != nil {
		return nil, err
	}
	st.Tracked = len(pairs)
	want := map[string]bool{}
	for _, p := range pairs {
		want["nvd:"+p.Vendor+":"+p.Product] = true
	}
	var oldest *time.Time
	covered := 0
	for _, f := range st.Feeds {
		if f.Status == "error" {
			st.Problems++
		}
		if f.Feed == "kev" {
			st.KEVAt = f.LastOK
			continue
		}
		if want[f.Feed] && f.LastOK != nil {
			covered++
			if oldest == nil || f.LastOK.Before(*oldest) {
				t := *f.LastOK
				oldest = &t
			}
		}
	}
	if covered == len(want) && covered > 0 {
		st.NVDAt = oldest
	}
	return st, nil
}

// ImportResult says what an uploaded file held.
type ImportResult struct {
	Kind  string `json:"kind"`
	Items int    `json:"items"`
}

// Import loads a feed file by hand: "kev" (the CISA catalog) or "nvd" (a saved page of the NVD CVE API answer). It is for
// feeds the server cannot download itself; large NVD files do not fit through the console's upload limit, so for those point
// the feed address at a mirror instead.
func (s *Service) Import(ctx context.Context, kind string, data []byte) (*ImportResult, error) {
	switch kind {
	case "kev":
		entries, err := ParseKEV(data)
		if err != nil {
			return nil, invalid("%v", err)
		}
		if err := s.Store.ApplyKEV(ctx, entries); err != nil {
			return nil, err
		}
		_ = s.Store.RecordFeed(ctx, "kev", true, "", "", len(entries))
		return &ImportResult{Kind: kind, Items: len(entries)}, nil
	case "nvd":
		p, err := ParseNVD(data, nil)
		if err != nil {
			return nil, invalid("%v", err)
		}
		seen := map[[2]string]bool{}
		var scope [][2]string
		for _, c := range p.CVEs {
			for _, r := range c.Ranges {
				k := [2]string{r.Vendor, r.Product}
				if !seen[k] {
					seen[k] = true
					scope = append(scope, k)
				}
			}
		}
		if err := s.Store.UpsertCVEs(ctx, p.CVEs, scope); err != nil {
			return nil, err
		}
		return &ImportResult{Kind: kind, Items: len(p.CVEs)}, nil
	}
	return nil, invalid("kind must be kev or nvd")
}
