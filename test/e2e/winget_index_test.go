package e2e

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	sconfig "github.com/auzring1/librepatch/internal/server/config"
)

// The winget index: status, a manual refresh (audited), search by name, and the fleet list of available software
// updates, over the real HTTP API.
func TestWingetIndexStatusRefreshSearchAndFleetUpdates(t *testing.T) {
	fixture, err := os.ReadFile("../../internal/server/wingetindex/testdata/mini-source2.msix")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(fixture) }))
	defer srv.Close()

	h := newHarnessCfg(t, 90*24*time.Hour, func(c *sconfig.Config) { c.WingetSource = "github" })
	h.setupAndLogin()
	// The test server serves plain http; production only accepts https (checked when the configuration is loaded).
	h.app.Winget.URL, h.app.Winget.AllowHTTP = srv.URL, true

	st, idx := h.do("GET", "/api/v1/catalog/index", nil, nil)
	if st != 200 || idx["enabled"] != true || num(idx["package_count"]) != 0 {
		t.Fatalf("status before the first download: %d %v", st, idx)
	}
	st, out := h.do("GET", "/api/v1/catalog/search?q=firefox", nil, nil)
	if st != 200 || out["index"] != nil {
		t.Fatalf("no index hits before the download: %d %v", st, out)
	}

	st, idx = h.do("POST", "/api/v1/catalog/index/refresh", map[string]any{}, nil)
	if st != 200 || num(idx["package_count"]) != 711 || idx["fetched_at"] == nil {
		t.Fatalf("refresh: %d %v", st, idx)
	}
	if h.auditCount("catalog.index_refresh") != 1 {
		t.Fatal("a manual refresh must be audited")
	}

	st, out = h.do("GET", "/api/v1/catalog/search?q=firefox", nil, nil)
	hits, _ := out["index"].([]any)
	if st != 200 || len(hits) != 2 || hits[0].(map[string]any)["identifier"] != "Mozilla.Firefox" || hits[0].(map[string]any)["in_catalog"] != false {
		t.Fatalf("search: %d %v", st, out)
	}

	st, fleet := h.do("GET", "/api/v1/software/updates", nil, nil)
	if st != 200 || fleet["items"] == nil || len(fleet["items"].([]any)) != 0 {
		t.Fatalf("fleet updates with no devices: %d %v", st, fleet)
	}
}

func TestWingetIndexIsOffWhenTheWingetSourceIsOff(t *testing.T) {
	h := newHarness(t) // WingetSource: off
	h.setupAndLogin()
	st, idx := h.do("GET", "/api/v1/catalog/index", nil, nil)
	if st != 200 || idx["enabled"] != false {
		t.Fatalf("%d %v", st, idx)
	}
	if st, _ := h.do("POST", "/api/v1/catalog/index/refresh", map[string]any{}, nil); st != 409 {
		t.Fatalf("refresh with the source off: %d", st)
	}
}
