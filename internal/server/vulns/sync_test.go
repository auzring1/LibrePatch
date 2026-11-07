package vulns

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/internal/server/kek"
	"github.com/auzring1/librepatch/internal/server/settings"
)

// nvdPage writes one page of an NVD answer holding the given CVEs (each a ready JSON object for "cve").
func nvdPage(start, total int, cves ...string) string {
	var items []string
	for _, c := range cves {
		items = append(items, `{"cve":`+c+`}`)
	}
	return `{"resultsPerPage":` + strconv.Itoa(len(cves)) + `,"startIndex":` + strconv.Itoa(start) + `,"totalResults":` + strconv.Itoa(total) + `,"format":"NVD_CVE","version":"2.0","vulnerabilities":[` + strings.Join(items, ",") + `]}`
}

func chromeCVE(id, end string) string {
	return `{"id":"` + id + `","published":"2026-09-30T20:15:00.123","lastModified":"2026-10-02T14:00:00.000","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"Chrome bug ` + id + `"}],` +
		`"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.8,"baseSeverity":"HIGH"}}]},` +
		`"configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*","versionEndExcluding":"` + end + `"}]}]}]}`
}

type feedServer struct {
	mu        sync.Mutex
	requests  []string // "nvd <virtualMatchString> start=<n> since=<param>" and "kev"
	keys      []string
	kevBody   string
	kevTag    string
	rateLimit map[string]bool // products to answer 429 for
	srv       *httptest.Server
}

func newFeedServer(t *testing.T) *feedServer {
	fs := &feedServer{kevBody: string(fixture(t, "kev.json")), kevTag: `"kev1"`, rateLimit: map[string]bool{}}
	fs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		switch r.URL.Path {
		case "/kev.json":
			fs.requests = append(fs.requests, "kev")
			if r.Header.Get("If-None-Match") == fs.kevTag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", fs.kevTag)
			_, _ = w.Write([]byte(fs.kevBody))
		case "/nvd":
			q := r.URL.Query()
			vms := q.Get("virtualMatchString")
			fs.requests = append(fs.requests, "nvd "+vms+" start="+q.Get("startIndex")+" since="+q.Get("lastModStartDate"))
			fs.keys = append(fs.keys, r.Header.Get("apiKey"))
			for p := range fs.rateLimit {
				if strings.Contains(vms, p) {
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
			}
			switch {
			case strings.HasSuffix(vms, "google:chrome"):
				if q.Get("startIndex") == "0" {
					_, _ = w.Write([]byte(nvdPage(0, 3, chromeCVE("CVE-2026-0001", "130.0.6723.58"), chromeCVE("CVE-2026-0010", "131.0.1"))))
				} else {
					_, _ = w.Write([]byte(nvdPage(2, 3, chromeCVE("CVE-2026-0011", "132.0"))))
				}
			default:
				_, _ = w.Write([]byte(string(fixture(t, "nvd_page.json"))))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

func (fs *feedServer) log() []string {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return append([]string(nil), fs.requests...)
}

func syncFixture(t *testing.T) (*fleet, *Service, *feedServer, *[]time.Duration, uuid.UUID) {
	f := newFleet(t)
	fs := newFeedServer(t)
	user := uuid.New()
	f.exec("INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, 'a@example.org', 'A', 'x')", user, f.org)
	sealer, err := kek.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	set := &settings.Service{Pool: f.pool, Sealer: sealer}
	var pauses []time.Duration
	clock := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	svc := &Service{Store: f.st, Settings: set, HTTP: fs.srv.Client(), Now: func() time.Time { return clock }, Sleep: func(_ context.Context, d time.Duration) { pauses = append(pauses, d) }}
	f.st.Now = svc.Now
	return f, svc, fs, &pauses, user
}

func enable(t *testing.T, f *fleet, svc *Service, user uuid.UUID, fs *feedServer, key string) {
	t.Helper()
	in := map[string]any{"enabled": true, "kev_url": fs.srv.URL + "/kev.json", "nvd_url": fs.srv.URL + "/nvd"}
	if key != "" {
		in["nvd_api_key"] = key
	}
	if _, err := svc.Settings.Put(context.Background(), settings.Actor{Org: f.org, User: user}, "vulnerabilities", 0, in); err != nil {
		t.Fatal(err)
	}
}

func TestSyncDownloadsWhatTheFleetNeeds(t *testing.T) {
	f, svc, fs, pauses, user := syncFixture(t)
	ctx := context.Background()
	if _, err := svc.Sync(ctx, f.org, false); !errors.Is(err, ErrOff) {
		t.Fatalf("a sync while the lookup is off: %v", err)
	}
	win := f.device("PC-OLD", "Windows 11 Pro", "26100.1000", "active")
	f.install(win, "Google Chrome", "129.0.6668.1")
	enable(t, f, svc, user, fs, "SECRET-KEY")

	rep, err := svc.Sync(ctx, f.org, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.KEV != "downloaded" || rep.KEVItems != 2 || rep.Products != 2 || rep.Pending != 0 || len(rep.Errors) != 0 || rep.Requests != 3 {
		t.Fatalf("report: %+v", rep)
	}
	log := fs.log()
	want := []string{"kev", "nvd cpe:2.3:a:google:chrome start=0 since=", "nvd cpe:2.3:a:google:chrome start=2 since=", "nvd cpe:2.3:o:microsoft:windows_11_24h2 start=0 since="}
	if strings.Join(log, "|") != strings.Join(want, "|") {
		t.Fatalf("requests:\n%v\nwant\n%v", log, want)
	}
	for _, k := range fs.keys {
		if k != "SECRET-KEY" {
			t.Fatalf("the API key must go with every NVD request: %v", fs.keys)
		}
	}
	// With a key the pause is short; there is one before every request after the first.
	if len(*pauses) != 2 || (*pauses)[0] != keyDelay {
		t.Fatalf("pauses: %v", *pauses)
	}

	items, sum, err := f.st.Overview(ctx, f.org, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	// Both pages of Chrome were read (0011 is on the second), and the old Chrome and Windows 11 match all of them.
	if sum.CVEs != 4 || ids(items) != "CVE-2026-0001,CVE-2026-0002,CVE-2026-0010,CVE-2026-0011" || !items[0].Exploited || items[2].Exploited {
		t.Fatalf("overview after a sync: %s %+v", ids(items), sum)
	}

	// Nothing is due a minute later.
	rep, err = svc.Sync(ctx, f.org, false)
	if err != nil || rep.KEV != "skipped" || rep.Products != 0 || rep.Requests != 0 {
		t.Fatalf("a second sync must find nothing due: %+v %v", rep, err)
	}
	// Forced: the CISA list answers 304 to its ETag, the NVD is asked only for what changed since last time.
	rep, err = svc.Sync(ctx, f.org, true)
	if err != nil || rep.KEV != "unchanged" || rep.Products != 2 {
		t.Fatalf("forced: %+v %v", rep, err)
	}
	var incremental int
	for _, l := range fs.log()[len(want):] {
		if strings.HasPrefix(l, "nvd") && !strings.HasSuffix(l, "since=") {
			incremental++
			if !strings.Contains(l, "since=2026-10-19T11:00:00.000") {
				t.Fatalf("the window starts an hour before the last success: %s", l)
			}
		}
	}
	if incremental < 2 {
		t.Fatalf("a second pass must ask only for changes: %v", fs.log())
	}
}

func TestWithoutAKeyTheSyncPausesLonger(t *testing.T) {
	f, svc, fs, pauses, user := syncFixture(t)
	f.install(f.device("PC", "Windows 11 Pro", "26100.1000", "active"), "Google Chrome", "129.0")
	enable(t, f, svc, user, fs, "")
	if _, err := svc.Sync(context.Background(), f.org, false); err != nil {
		t.Fatal(err)
	}
	for _, p := range *pauses {
		if p != noKeyDelay {
			t.Fatalf("without a key the NVD allows 5 requests per 30 seconds: %v", *pauses)
		}
	}
	if len(*pauses) == 0 {
		t.Fatal("no pause between requests")
	}
}

func TestARateLimitStopsTheRunAndKeepsWhatWasDone(t *testing.T) {
	f, svc, fs, _, user := syncFixture(t)
	ctx := context.Background()
	f.install(f.device("PC", "Windows 11 Pro", "26100.1000", "active"), "Google Chrome", "129.0")
	enable(t, f, svc, user, fs, "")
	fs.mu.Lock()
	fs.rateLimit["windows_11_24h2"] = true
	fs.mu.Unlock()
	rep, err := svc.Sync(ctx, f.org, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.KEV != "downloaded" || rep.Products != 1 || rep.Pending != 1 || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0], "rate limit") {
		t.Fatalf("report: %+v", rep)
	}
	feeds, _ := f.st.Feeds(ctx)
	status := map[string]string{}
	for _, fd := range feeds {
		status[fd.Feed] = fd.Status
	}
	if status["kev"] != "ok" || status["nvd:google:chrome"] != "ok" || status["nvd:microsoft:windows_11_24h2"] != "error" {
		t.Fatalf("feed states: %v", status)
	}
	// Next run: only the product that failed is asked again.
	fs.mu.Lock()
	delete(fs.rateLimit, "windows_11_24h2")
	fs.mu.Unlock()
	before := len(fs.log())
	rep, err = svc.Sync(ctx, f.org, false)
	if err != nil || rep.Products != 1 || rep.KEV != "skipped" {
		t.Fatalf("retry: %+v %v", rep, err)
	}
	if got := fs.log()[before:]; len(got) != 1 || !strings.Contains(got[0], "windows_11_24h2") {
		t.Fatalf("only the failed product is asked again: %v", got)
	}
}

func TestABrokenCISAListKeepsTheOldMarks(t *testing.T) {
	f, svc, fs, _, user := syncFixture(t)
	ctx := context.Background()
	f.device("PC", "Windows 11 Pro", "26100.1000", "active")
	enable(t, f, svc, user, fs, "")
	if _, err := svc.Sync(ctx, f.org, false); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.st.Counts(ctx); n.Exploited != 2 {
		t.Fatalf("exploited marks: %+v", n)
	}
	fs.mu.Lock()
	fs.kevBody, fs.kevTag = `{"vulnerabilities":[]}`, `"kev2"`
	fs.mu.Unlock()
	rep, err := svc.Sync(ctx, f.org, true)
	if err != nil || rep.KEV != "failed" || len(rep.Errors) == 0 {
		t.Fatalf("report: %+v %v", rep, err)
	}
	if n, _ := f.st.Counts(ctx); n.Exploited != 2 {
		t.Fatalf("an empty list must not clear the exploited marks: %+v", n)
	}
	feeds, _ := f.st.Feeds(ctx)
	for _, fd := range feeds {
		if fd.Feed == "kev" && (fd.Status != "error" || fd.LastOK == nil) {
			t.Fatalf("the CISA feed must say it failed and keep its last success: %+v", fd)
		}
	}
}

func TestOnlyOneSyncRunsAtATime(t *testing.T) {
	f, svc, fs, _, user := syncFixture(t)
	f.device("PC", "Windows 11 Pro", "26100.1000", "active")
	enable(t, f, svc, user, fs, "")
	svc.mu.Lock()
	svc.running = true
	svc.mu.Unlock()
	if _, err := svc.Sync(context.Background(), f.org, false); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second sync while one runs: %v", err)
	}
}

func TestCPEEscape(t *testing.T) {
	for in, want := range map[string]string{"chrome": "chrome", "notepad++": `notepad\+\+`, "vlc_media_player": "vlc_media_player", "7-zip": "7-zip", "a:b": `a\:b`} {
		if got := cpeEscape(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	b, _ := json.Marshal(nvdTimeParam(time.Date(2026, 1, 2, 3, 4, 5, 6000000, time.UTC)))
	if string(b) != `"2026-01-02T03:04:05.006"` {
		t.Fatalf("the NVD's date format: %s", b)
	}
}
