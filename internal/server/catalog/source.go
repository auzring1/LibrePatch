package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/auzring1/librepatch/internal/shared/brand"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/auzring1/librepatch/internal/shared/vercmp"
)

// Source provides winget manifests. Only the official winget-pkgs repository is
// implemented; the interface lets tests (and later the CDN index) plug in.
type Source interface {
	// Versions lists the versions of a package, newest first.
	Versions(ctx context.Context, identifier string) ([]string, error)
	// Manifests returns the manifest files of one version.
	Manifests(ctx context.Context, identifier, version string) ([][]byte, error)
}

// ErrNotFound means the package or version does not exist in the source.
var ErrNotFound = errors.New("catalog: not found in the winget repository")

// GitHubSource reads microsoft/winget-pkgs through raw.githubusercontent.com
// (manifests) and the GitHub contents API (version listing). The listing needs
// the API; without it callers must name a version.
type GitHubSource struct {
	Client  *http.Client
	RawBase string // default https://raw.githubusercontent.com/microsoft/winget-pkgs/master
	APIBase string // default https://api.github.com/repos/microsoft/winget-pkgs
	Token   string // optional, raises the API rate limit
}

func (g *GitHubSource) client() *http.Client {
	if g.Client != nil {
		return g.Client
	}
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 3 || r.URL.Scheme != "https" {
			return errors.New("redirect refused")
		}
		return nil
	}}
}

func (g *GitHubSource) raw() string {
	if g.RawBase != "" {
		return strings.TrimRight(g.RawBase, "/")
	}
	return "https://raw.githubusercontent.com/microsoft/winget-pkgs/master"
}

func (g *GitHubSource) api() string {
	if g.APIBase != "" {
		return strings.TrimRight(g.APIBase, "/")
	}
	return "https://api.github.com/repos/microsoft/winget-pkgs"
}

// dir is manifests/<first letter>/<Publisher>/<Package>[/...] for an identifier.
func dir(identifier string) (string, error) {
	if !ValidIdentifier(identifier) {
		return "", fmt.Errorf("%w: invalid package identifier", ErrManifest)
	}
	segs := strings.Split(identifier, ".")
	for i, s := range segs {
		if s == "" || s == ".." {
			return "", fmt.Errorf("%w: invalid package identifier", ErrManifest)
		}
		segs[i] = url.PathEscape(s)
	}
	first := strings.ToLower(identifier[:1])
	return "manifests/" + url.PathEscape(first) + "/" + strings.Join(segs, "/"), nil
}

func (g *GitHubSource) get(ctx context.Context, u string, max int64, api bool) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", brand.Name+"-Server")
	if api {
		req.Header.Set("Accept", "application/vnd.github+json")
		if g.Token != "" {
			req.Header.Set("Authorization", "Bearer "+g.Token)
		}
	}
	resp, err := g.client().Do(req) // #nosec G107 G704 -- fixed GitHub hosts plus a validated path
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if int64(len(b)) > max {
		return nil, resp.StatusCode, errors.New("response too large")
	}
	return b, resp.StatusCode, nil
}

// Versions implements Source.
func (g *GitHubSource) Versions(ctx context.Context, id string) ([]string, error) {
	d, err := dir(id)
	if err != nil {
		return nil, err
	}
	b, code, err := g.get(ctx, g.api()+"/contents/"+d, 4<<20, true)
	if err != nil {
		return nil, err
	}
	switch code {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, ErrNotFound
	case http.StatusForbidden, http.StatusTooManyRequests:
		return nil, errors.New("the GitHub API refused the request (rate limit or no access); name a version instead")
	default:
		return nil, fmt.Errorf("GitHub API answered HTTP %d", code)
	}
	var entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, errors.New("unexpected GitHub API response")
	}
	var vs []string
	for _, e := range entries {
		// version directories start with a digit (or v+digit); other directories are sub-packages
		if e.Type == "dir" && looksLikeVersion(e.Name) && vercmp.Key(e.Name) != nil {
			vs = append(vs, e.Name)
		}
	}
	sort.Slice(vs, func(i, j int) bool { return vercmp.Compare(vs[i], vs[j]) > 0 })
	return vs, nil
}

func looksLikeVersion(s string) bool {
	if s == "" {
		return false
	}
	if s[0] >= '0' && s[0] <= '9' {
		return true
	}
	return len(s) > 1 && (s[0] == 'v' || s[0] == 'V') && s[1] >= '0' && s[1] <= '9'
}

// Manifests implements Source.
func (g *GitHubSource) Manifests(ctx context.Context, id, version string) ([][]byte, error) {
	d, err := dir(id)
	if err != nil {
		return nil, err
	}
	if !looksLikeVersion(version) || strings.ContainsAny(version, `/\`) || len(version) > 128 {
		return nil, fmt.Errorf("%w: invalid version", ErrManifest)
	}
	base := g.raw() + "/" + d + "/" + url.PathEscape(version) + "/" + url.PathEscape(id)
	main, code, err := g.get(ctx, base+".yaml", MaxManifestBytes, false)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GitHub answered HTTP %d", code)
	}
	var head struct {
		ManifestType  string `yaml:"ManifestType"`
		DefaultLocale string `yaml:"DefaultLocale"`
	}
	if err := yaml.Unmarshal(main, &head); err != nil {
		return nil, bad("YAML: %v", err)
	}
	if strings.EqualFold(head.ManifestType, "singleton") {
		return [][]byte{main}, nil
	}
	files := [][]byte{main}
	inst, code, err := g.get(ctx, base+".installer.yaml", MaxManifestBytes, false)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("installer manifest not found (HTTP %d)", code)
	}
	files = append(files, inst)
	loc := head.DefaultLocale
	if loc == "" || strings.ContainsAny(loc, `/\.`) || len(loc) > 20 {
		loc = "en-US"
	}
	if lb, code, err := g.get(ctx, base+".locale."+loc+".yaml", MaxManifestBytes, false); err == nil && code == http.StatusOK {
		files = append(files, lb)
	}
	return files, nil
}
