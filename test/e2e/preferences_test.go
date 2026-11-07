package e2e

import (
	"strings"
	"testing"
)

func TestPreferencesAndThemePolicy(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	op := h.orgUser("op@example.com", "operator")

	// Empty until chosen.
	st, b := h.do("GET", "/api/v1/me/preferences", nil, nil)
	if st != 200 || b["theme"] != "" || b["density"] != "" || len(b["views"].(map[string]any)) != 0 {
		t.Fatalf("defaults: %d %v", st, b)
	}
	view := map[string]any{"id": "mine", "name": "Offline laptops", "state": map[string]any{"sort": "hostname", "hidden": []string{"agent"}}}
	good := map[string]any{"theme": "midnight", "density": "compact", "views": map[string]any{"devices": []any{view}}}
	if st, b := h.do("PUT", "/api/v1/me/preferences", good, nil); st != 200 || b["theme"] != "midnight" {
		t.Fatalf("save: %d %v", st, b)
	}
	// It follows the account: another browser session of the same user sees it; another user does not.
	st, b = h.do("GET", "/api/v1/me/preferences", nil, nil)
	if st != 200 || b["theme"] != "midnight" || b["density"] != "compact" || len(b["views"].(map[string]any)["devices"].([]any)) != 1 {
		t.Fatalf("read back: %d %v", st, b)
	}
	if _, b := op.do("GET", "/api/v1/me/preferences", nil, nil); b["theme"] != "" {
		t.Fatalf("another user must not see it: %v", b)
	}
	if st, _ := op.do("PUT", "/api/v1/me/preferences", map[string]any{"theme": "slate"}, nil); st != 200 {
		t.Fatalf("operator save: %d", st)
	}
	if _, b := h.do("GET", "/api/v1/me/preferences", nil, nil); b["theme"] != "midnight" {
		t.Fatal("one user's save changed another's preferences")
	}

	// Validation.
	long := strings.Repeat("x", 61)
	for name, in := range map[string]map[string]any{
		"theme shape":    {"theme": "Dark Mode!"},
		"density":        {"density": "huge"},
		"table id":       {"views": map[string]any{"Bad Table": []any{}}},
		"view name":      {"views": map[string]any{"devices": []any{map[string]any{"id": "a", "name": long, "state": map[string]any{}}}}},
		"view id":        {"views": map[string]any{"devices": []any{map[string]any{"id": "A B", "name": "n", "state": map[string]any{}}}}},
		"view state":     {"views": map[string]any{"devices": []any{map[string]any{"id": "a", "name": "n", "state": []any{1}}}}},
		"view too large": {"views": map[string]any{"devices": []any{map[string]any{"id": "a", "name": "n", "state": map[string]any{"x": strings.Repeat("y", 5000)}}}}},
		"duplicate id":   {"views": map[string]any{"devices": []any{view, view}}},
	} {
		st, b := h.do("PUT", "/api/v1/me/preferences", in, nil)
		if st != 422 {
			t.Errorf("%s: %d %v", name, st, b)
		}
	}
	if _, b := h.do("GET", "/api/v1/me/preferences", nil, nil); b["theme"] != "midnight" {
		t.Fatal("a refused save changed the stored preferences")
	}
	// No session / a token.
	if st, _ := h.otherClient().do("GET", "/api/v1/me/preferences", nil, nil); st != 401 {
		t.Fatalf("anonymous: %d", st)
	}
	_, tok := h.do("POST", "/api/v1/me/api-tokens", map[string]any{"name": "t", "scopes": []string{"devices:read"}, "expires_in_days": 5}, nil)
	if st, _ := h.bearer(tok["token"].(string), "PUT", "/api/v1/me/preferences", map[string]any{"theme": "dark"}); st != 403 {
		t.Fatalf("token save: %d", st)
	}

	// The organization's default and offered themes: administrators only, audited, validated.
	if st, _ := op.do("PUT", "/api/v1/settings/branding", map[string]any{"default_theme": "dark"}, nil); st != 403 {
		t.Fatalf("operator changing the default theme: %d", st)
	}
	bad := map[string]any{"org_name": "Acme", "default_theme": "slate", "allowed_themes": []string{"light", "dark"}}
	if st, b := h.do("PUT", "/api/v1/settings/branding", bad, nil); st != 422 || !strings.Contains(toString(b), "default_theme") {
		t.Fatalf("default not offered: %d %v", st, b)
	}
	if st, _ := h.do("PUT", "/api/v1/settings/branding", map[string]any{"org_name": "Acme", "allowed_themes": []string{"light", "light"}}, nil); st != 422 {
		t.Fatalf("duplicate theme: %d", st)
	}
	ok := map[string]any{"org_name": "Acme", "default_theme": "dark", "allowed_themes": []string{"light", "dark"}}
	if st, b := h.do("PUT", "/api/v1/settings/branding", ok, nil); st != 200 {
		t.Fatalf("set policy: %d %v", st, b)
	}
	d := h.auditDetails("branding.update")
	if d["after"].(map[string]any)["default_theme"] != "dark" || d["after"].(map[string]any)["allowed_themes"] != "light,dark" {
		t.Fatalf("audit: %v", d)
	}
	_, pub := h.otherClient().do("GET", "/api/v1/branding", nil, nil)
	if pub["default_theme"] != "dark" || len(pub["allowed_themes"].([]any)) != 2 {
		t.Fatalf("public: %v", pub)
	}
	// Restriction applies to what people save.
	if st, _ := op.do("PUT", "/api/v1/me/preferences", map[string]any{"theme": "slate"}, nil); st != 422 {
		t.Fatalf("a theme the organization does not offer: %d", st)
	}
	if st, _ := op.do("PUT", "/api/v1/me/preferences", map[string]any{"theme": "light"}, nil); st != 200 {
		t.Fatalf("an offered theme: %d", st)
	}
	if st, _ := op.do("PUT", "/api/v1/me/preferences", map[string]any{"theme": ""}, nil); st != 200 {
		t.Fatalf("back to the organization default: %d", st)
	}
	// Reset clears the policy too.
	if st, _ := h.do("POST", "/api/v1/settings/branding/reset", map[string]any{}, nil); st != 200 {
		t.Fatal("reset")
	}
	_, pub = h.otherClient().do("GET", "/api/v1/branding", nil, nil)
	if pub["default_theme"] != "" || len(pub["allowed_themes"].([]any)) != 0 {
		t.Fatalf("after reset: %v", pub)
	}
}
