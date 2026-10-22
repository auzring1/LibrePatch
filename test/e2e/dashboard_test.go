package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func num(v any) int { f, _ := v.(float64); return int(f) }

func TestDashboardNotificationsAndLayoutPreferences(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()

	st, branch := h.do("POST", "/api/v1/sites", map[string]any{"name": "Branch"}, nil)
	if st != 201 {
		t.Fatalf("site: %d %v", st, branch)
	}
	_, tk := h.do("POST", "/api/v1/enrollment-tokens", map[string]any{"name": "branch", "max_uses": 5, "expires_in_hours": 1, "require_approval": false, "site_id": branch["id"]}, nil)
	taHead := h.startAgent(h.createToken("head", 5, false), &fakeHW{host: "HQ-1", serial: "S1", uuid: "U1"}, nil)
	taBranch := h.startAgent(tk["enrollment_string"].(string), &fakeHW{host: "BR-1", serial: "S2", uuid: "U2"}, nil)
	waitFor(t, 20*time.Second, "both agents connected", func() bool {
		return taHead.state() == "connected" && taBranch.state() == "connected" && len(h.devices()) == 2
	})

	// An administrator sees every section.
	st, d := h.do("GET", "/api/v1/dashboard", nil, nil)
	if st != 200 {
		t.Fatalf("dashboard: %d %v", st, d)
	}
	dev := d["devices"].(map[string]any)
	if num(dev["total"]) != 2 || num(dev["online"]) != 2 || num(dev["offline"]) != 0 {
		t.Fatalf("device tiles: %v", dev)
	}
	for _, k := range []string{"needs_restart", "missing_critical_devices", "failed_jobs_24h", "compliance", "held_updates", "software"} {
		if d[k] == nil {
			t.Errorf("an administrator should get %q: %v", k, d)
		}
	}
	if len(d["agent_versions"].([]any)) == 0 || len(d["activity"].([]any)) == 0 {
		t.Fatalf("agent versions and activity: %v", d)
	}

	// The site switcher narrows the numbers to one site; a bad id is refused.
	_, ds := h.do("GET", "/api/v1/dashboard?site="+branch["id"].(string), nil, nil)
	if num(ds["devices"].(map[string]any)["total"]) != 1 {
		t.Fatalf("one site: %v", ds["devices"])
	}
	if st, _ := h.do("GET", "/api/v1/dashboard?site=nope", nil, nil); st != 400 {
		t.Fatalf("bad site: %d", st)
	}

	// The hourly snapshot feeds the chart; running it again the same day overwrites the row.
	org := uuid.MustParse(h.session()["org"].(map[string]any)["id"].(string))
	for range 2 {
		if err := h.app.Dashboard.Snapshot(context.Background(), org); err != nil {
			t.Fatal(err)
		}
	}
	_, d = h.do("GET", "/api/v1/dashboard", nil, nil)
	hist := d["compliance"].(map[string]any)["history"].([]any)
	if len(hist) != 1 {
		t.Fatalf("history: %v", hist)
	}
	p := hist[0].(map[string]any)
	if num(p["compliant"])+num(p["non_compliant"])+num(p["unknown"]) != 2 {
		t.Fatalf("snapshot counts both devices: %v", p)
	}

	// A read-only user gets device and update numbers but no audit trail.
	ro := h.orgUser("ro@example.com", "readonly")
	st, d = ro.do("GET", "/api/v1/dashboard", nil, nil)
	if st != 200 || d["devices"] == nil || d["compliance"] == nil || len(d["activity"].([]any)) != 0 {
		t.Fatalf("read-only dashboard: %d %v", st, d)
	}

	// A site-limited technician sees only their own site.
	st, nu := h.do("POST", "/api/v1/users", map[string]any{"email": "tech@example.com", "display_name": "Tess",
		"roles": []map[string]any{{"role": "operator", "scope_type": "site", "scope_id": branch["id"]}}}, nil)
	if st != 201 {
		t.Fatalf("tech: %d %v", st, nu)
	}
	tech := h.otherClient()
	tech.signInNewUser("tech@example.com", nu["temporary_password"].(string), "Quartz-Harbor-Violin-77", true)
	st, d = tech.do("GET", "/api/v1/dashboard", nil, nil)
	if st != 200 || num(d["devices"].(map[string]any)["total"]) != 1 {
		t.Fatalf("site-limited dashboard must count one device: %d %v", st, d)
	}
	if d["held_updates"] != nil || len(d["activity"].([]any)) != 0 {
		t.Fatalf("site-limited users get no organization-wide sections: %v", d)
	}
	for _, a := range d["attention"].([]any) {
		if a.(map[string]any)["hostname"] == "HQ-1" {
			t.Fatalf("another site's device in attention: %v", a)
		}
	}
	hist = d["compliance"].(map[string]any)["history"].([]any)
	if len(hist) != 1 || num(hist[0].(map[string]any)["compliant"])+num(hist[0].(map[string]any)["non_compliant"])+num(hist[0].(map[string]any)["unknown"]) != 1 {
		t.Fatalf("site-limited history: %v", hist)
	}

	// Anonymous callers and tokens.
	if st, _ := h.otherClient().do("GET", "/api/v1/dashboard", nil, nil); st != 401 {
		t.Fatalf("anonymous dashboard: %d", st)
	}
	if st, _ := h.otherClient().do("GET", "/api/v1/notifications", nil, nil); st != 401 {
		t.Fatalf("anonymous notifications: %d", st)
	}
	st, n := h.do("GET", "/api/v1/notifications", nil, nil)
	if st != 200 || n["items"] == nil {
		t.Fatalf("notifications: %d %v", st, n)
	}

	// Layout preferences: validated, stored, and kept when an older client saves only a theme.
	layout := map[string]any{"nav": map[string]any{"collapsed": true, "closed": []string{"updates"}}, "dashboard": map[string]any{"order": []string{"compliance", "tiles"}, "hidden": []string{"agents"}}}
	if st, b := h.do("PUT", "/api/v1/me/preferences", layout, nil); st != 200 {
		t.Fatalf("layout: %d %v", st, b)
	}
	if st, _ := h.do("PUT", "/api/v1/me/preferences", map[string]any{"theme": "dark"}, nil); st != 200 {
		t.Fatal("theme only")
	}
	_, pr := h.do("GET", "/api/v1/me/preferences", nil, nil)
	if pr["nav"].(map[string]any)["collapsed"] != true || len(pr["dashboard"].(map[string]any)["order"].([]any)) != 2 {
		t.Fatalf("an older client must not wipe the layout: %v", pr)
	}
	for name, in := range map[string]map[string]any{
		"nav id":          {"nav": map[string]any{"closed": []string{"Bad Id"}}},
		"nav duplicate":   {"nav": map[string]any{"closed": []string{"a", "a"}}},
		"dashboard hide":  {"dashboard": map[string]any{"hidden": []string{"x y"}}},
		"dashboard order": {"dashboard": map[string]any{"order": make([]string, 40)}},
	} {
		if st, b := h.do("PUT", "/api/v1/me/preferences", in, nil); st != 422 {
			t.Errorf("%s: %d %v", name, st, b)
		}
	}
}
