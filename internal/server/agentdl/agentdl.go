// Package agentdl gives the console and the endpoints the agent installers (the exe and the MSI) without anyone having to
// visit GitHub (decision D112).
//
// The server fetches the two files from the release that matches its own version, once, checks them against the
// published SHA-256 file, and keeps them on the content volume. The console then offers them, and the install commands it
// prints (curl plus msiexec, or curl plus the exe) point at the server itself, so an endpoint only ever talks to the
// LibrePatch server.
//
// Trust: the files come from the project's GitHub release over HTTPS, and the SHA-256 file is published beside them; that
// protects against a damaged download, not against a compromised release. The agent files are not Authenticode-signed
// (docs/THREAT-MODEL.md). A mirror can be named with LIBREPATCH_AGENT_DOWNLOAD_BASE_URL.
package agentdl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DefaultBaseURL is where the project publishes its releases; the files of version V are under <base>/server-V/.
const DefaultBaseURL = "https://github.com/auzring1/LibrePatch/releases/download"

// Kind names one of the two installers.
type Kind string

const (
	MSI Kind = "msi"
	EXE Kind = "exe"
)

// Kinds lists the installers in the order the console shows them.
var Kinds = []Kind{MSI, EXE}

const (
	maxFile    = 256 << 20 // the agent is about 15 MB
	maxSumFile = 4 << 10
)

// Item is one installer that is ready to be served.
type Item struct {
	Kind     Kind   `json:"kind"`
	FileName string `json:"file_name"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
	// Verified is true when the SHA-256 matched the one published next to the file.
	Verified bool   `json:"verified"`
	path     string // on disk
}

// Status is what the console shows.
type Status struct {
	Enabled   bool       `json:"enabled"`
	Version   string     `json:"version"`
	Reason    string     `json:"reason,omitempty"` // why it is not enabled
	Items     []Item     `json:"items"`
	CheckedAt *time.Time `json:"checked_at"`
	Error     string     `json:"error,omitempty"`
}

// Service fetches, keeps and serves the installers.
type Service struct {
	// Dir is where files are kept (a folder on the content volume). Empty disables the service.
	Dir string
	// Version is the server's own version; files are fetched from the release of the same number.
	Version string
	// BaseURL overrides DefaultBaseURL (a mirror). https only unless AllowHTTP.
	BaseURL string
	// Off turns the feature off (LIBREPATCH_AGENT_DOWNLOADS=off).
	Off       bool
	Client    *http.Client
	Log       *slog.Logger
	AllowHTTP bool // tests only
	Now       func() time.Time

	mu      sync.RWMutex
	items   map[Kind]Item
	checked *time.Time
	lastErr string
}

var releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

// reason returns why the service cannot work ("" when it can).
func (s *Service) reason() string {
	switch {
	case s.Off:
		return "Agent downloads are turned off on this server (LIBREPATCH_AGENT_DOWNLOADS=off)."
	case s.Dir == "":
		return "This server has no content folder to keep the files in."
	case !releaseVersion.MatchString(s.Version) || strings.HasPrefix(s.Version, "0.0.0-edge") || strings.HasSuffix(s.Version, "-dev"):
		return "This is a development or test build of the server, so there is no release to take the agent from."
	}
	return ""
}

// Enabled reports whether the service can work at all.
func (s *Service) Enabled() bool { return s != nil && s.reason() == "" }

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

func (s *Service) base() string {
	b := s.BaseURL
	if b == "" {
		b = DefaultBaseURL
	}
	return strings.TrimRight(b, "/")
}

func (s *Service) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 || (r.URL.Scheme != "https" && !s.AllowHTTP) {
			return errors.New("redirect refused")
		}
		return nil
	}}
}

// FileName is the name the release uses for the installer of this kind and version.
func FileName(k Kind, version string) string {
	if k == MSI {
		return "librepatch-agent_" + version + "_windows_x64.msi"
	}
	return "librepatch-agent_" + version + "_windows_amd64.exe"
}

func (s *Service) releaseURL(name string) string {
	return s.base() + "/server-" + url.PathEscape(s.Version) + "/" + url.PathEscape(name)
}

func (s *Service) versionDir() string { return filepath.Join(s.Dir, s.Version) }

// Get returns an installer that is ready to be served.
func (s *Service) Get(k Kind) (Item, bool) {
	if s == nil {
		return Item{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	it, ok := s.items[k]
	return it, ok
}

// Open opens the file of a ready installer.
func (it Item) Open() (*os.File, error) { return os.Open(it.path) }

// Status describes the state for the console.
func (s *Service) Status() Status {
	if s == nil {
		return Status{Reason: "Agent downloads are not set up on this server.", Items: []Item{}}
	}
	st := Status{Version: s.Version, Items: []Item{}}
	if r := s.reason(); r != "" {
		st.Reason = r
		return st
	}
	st.Enabled = true
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range Kinds {
		if it, ok := s.items[k]; ok {
			st.Items = append(st.Items, it)
		}
	}
	st.CheckedAt = s.checked
	st.Error = s.lastErr
	return st
}

// Ready reports whether every installer is available.
func (s *Service) Ready() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items) == len(Kinds)
}

// Refresh makes sure both installers are on disk and checked. It is safe to call repeatedly: a file that is already
// there and matches its recorded hash is not fetched again.
func (s *Service) Refresh(ctx context.Context) error {
	if r := s.reason(); r != "" {
		return errors.New(r)
	}
	if err := os.MkdirAll(s.versionDir(), 0o750); err != nil {
		return s.record(nil, err)
	}
	found := map[Kind]Item{}
	var firstErr error
	for _, k := range Kinds {
		it, err := s.ensure(ctx, k)
		if err != nil {
			s.log().Warn("agent installer not available", "kind", string(k), "err", err)
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", k, err)
			}
			continue
		}
		found[k] = it
	}
	s.tidy()
	return s.record(found, firstErr)
}

func (s *Service) record(found map[Kind]Item, err error) error {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if found != nil {
		s.items = found
	}
	s.checked = &now
	s.lastErr = ""
	if err != nil {
		s.lastErr = err.Error()
	}
	return err
}

// ensure returns the installer of kind k, fetching it if it is not on disk yet.
func (s *Service) ensure(ctx context.Context, k Kind) (Item, error) {
	name := FileName(k, s.Version)
	path := filepath.Join(s.versionDir(), name)
	sumPath := path + ".sha256"
	// Already fetched earlier (also after a restart): trust it only if it still matches the hash recorded when it was fetched.
	if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
		if want, rerr := os.ReadFile(sumPath); rerr == nil { // #nosec G304 -- a file this service wrote, under its own folder
			got, size, herr := hashFile(path)
			fields := strings.Fields(string(want))
			if herr == nil && len(fields) >= 1 && strings.EqualFold(fields[0], got) {
				return Item{Kind: k, FileName: name, Size: size, SHA256: got, Verified: len(fields) >= 2 && fields[1] == "verified", path: path}, nil
			}
			s.log().Warn("a stored agent installer no longer matches its recorded hash; fetching it again", "file", name)
		}
	}
	return s.fetch(ctx, k, name, path, sumPath)
}

func (s *Service) fetch(ctx context.Context, k Kind, name, path, sumPath string) (Item, error) {
	tmp, err := os.CreateTemp(s.versionDir(), "download-*")
	if err != nil {
		return Item{}, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	h := sha256.New()
	size, err := s.get(ctx, s.releaseURL(name), io.MultiWriter(tmp, h), maxFile, false)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Item{}, err
	}
	if size == 0 {
		return Item{}, errors.New("the download is empty")
	}
	got := hex.EncodeToString(h.Sum(nil))

	// The published hash is optional (older releases have none for the MSI) but, when there, it must match.
	verified := false
	var sum strings.Builder
	switch _, serr := s.get(ctx, s.releaseURL(name+".sha256"), &sum, maxSumFile, true); {
	case serr == nil:
		fields := strings.Fields(sum.String())
		if len(fields) == 0 || !regexp.MustCompile(`^[0-9a-fA-F]{64}$`).MatchString(fields[0]) {
			return Item{}, errors.New("the published SHA-256 file is not in the expected format")
		}
		if !strings.EqualFold(fields[0], got) {
			return Item{}, fmt.Errorf("the download does not match the published SHA-256 (got %s, published %s)", got, strings.ToLower(fields[0]))
		}
		verified = true
	case errors.Is(serr, errNotFound):
		s.log().Warn("no published SHA-256 for the agent installer; keeping the hash computed here", "file", name)
	default:
		return Item{}, fmt.Errorf("fetch the published SHA-256: %w", serr)
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return Item{}, err
	}
	rec := got
	if verified {
		rec += " verified"
	}
	if err := os.WriteFile(sumPath, []byte(rec+"\n"), 0o600); err != nil {
		return Item{}, err
	}
	s.log().Info("agent installer fetched", "file", name, "bytes", size, "verified", verified)
	return Item{Kind: k, FileName: name, Size: size, SHA256: got, Verified: verified, path: path}, nil
}

var errNotFound = errors.New("not found")

// get streams url into w, refusing more than max bytes. When missingOK is set a 404 is errNotFound.
func (s *Service) get(ctx context.Context, rawURL string, w io.Writer, max int64, missingOK bool) (int64, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(s.AllowHTTP && u.Scheme == "http")) {
		return 0, fmt.Errorf("%q is not an https address", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "librepatch-server/"+s.Version)
	resp, err := s.client().Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound && missingOK {
		return 0, errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("%s answered HTTP %d", u.Host, resp.StatusCode)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, max+1))
	if err != nil {
		return n, err
	}
	if n > max {
		return n, fmt.Errorf("the download is larger than %d MB", max>>20)
	}
	return n, nil
}

// tidy removes the files of other versions (an older server's) from the folder.
func (s *Service) tidy() {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && e.Name() != s.Version && releaseVersion.MatchString(e.Name()) {
			_ = os.RemoveAll(filepath.Join(s.Dir, e.Name()))
		}
	}
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path) // #nosec G304 -- a file the service wrote itself
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// Run fetches the installers in the background, retrying with growing pauses until both are there, then looks again
// once a day (it only notices a missing or damaged file; nothing is fetched while the stored files are fine).
func (s *Service) Run(ctx context.Context) {
	if !s.Enabled() {
		if s != nil {
			s.log().Info("agent downloads are not available", "reason", s.reason())
		}
		return
	}
	pauses := []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour}
	failures := 0
	for {
		wait := 24 * time.Hour
		if err := s.Refresh(ctx); err != nil {
			wait = pauses[min(failures, len(pauses)-1)]
			failures++
		} else {
			failures = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
