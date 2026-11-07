package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// An API token can carry settings:write, which opens the master-key routes. The key must stay with a signed-in person.
func TestMasterKeyRefusesAPITokens(t *testing.T) {
	rec := httptest.NewRecorder()
	if requireInteractive(rec, &Principal{TokenID: "tok"}) {
		t.Fatal("a token must be refused")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a token must get 403, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	if !requireInteractive(rec, &Principal{}) || rec.Code != http.StatusOK {
		t.Fatalf("a console session must pass, status %d", rec.Code)
	}
}
