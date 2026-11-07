package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/auzring1/librepatch/internal/server/masterkey"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

// A stack that generated its own master key makes the first administrator save it before anything else works (D109).
func TestMasterKeyMustBeSavedFirst(t *testing.T) {
	var keyHex string
	h := newHarnessPrep(t, 90*24*time.Hour, nil, func(db *pgtest.DB, key []byte) {
		// What the maintenance service does on the first start of a new stack.
		id, err := masterkey.ID(key)
		if err != nil {
			t.Fatal(err)
		}
		owner, err := pgx.Connect(context.Background(), db.OwnerURL)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = owner.Close(context.Background()) }()
		if _, err := owner.Exec(context.Background(), `INSERT INTO master_key_ack (id, key_id) VALUES (1, $1)`, id); err != nil {
			t.Fatal(err)
		}
		keyHex = masterkey.Hex(key)
	})
	h.setupAndLogin()

	if _, b := h.do("GET", "/api/v1/auth/session", nil, nil); b["master_key_pending"] != true {
		t.Fatalf("session must say the key is pending: %v", b)
	}
	// Everything else is refused, whatever the permission.
	for _, p := range []string{"/api/v1/devices", "/api/v1/audit", "/api/v1/enrollment-tokens", "/api/v1/updates"} {
		st, b := h.do("GET", p, nil, nil)
		if st != 403 || b["error"].(map[string]any)["code"] != "master_key_unconfirmed" {
			t.Fatalf("GET %s while the key is pending: %d %v", p, st, b)
		}
	}
	if st, _ := h.do("GET", "/api/v1/me/preferences", nil, nil); st != 200 {
		t.Fatalf("the key screen needs the preferences: %d", st)
	}

	// The key is shown, and the view is audited.
	st, k := h.do("GET", "/api/v1/security/master-key", nil, nil)
	if st != 200 || strings.ReplaceAll(k["key"].(string), "-", "") != keyHex {
		t.Fatalf("show the key: %d %v", st, k)
	}
	if id, _ := masterkey.ID(h.app.Cfg.MasterKey); k["key_id"] != id {
		t.Fatalf("key id: %v", k["key_id"])
	}
	if h.auditCount("master_key.view") != 1 {
		t.Fatal("showing the key must be audited")
	}

	// Confirming needs the end of the key, not just a click.
	for _, bad := range []string{"", "000000", keyHex[len(keyHex)-5:], keyHex[:6]} {
		if st, _ := h.do("POST", "/api/v1/security/master-key/acknowledge", map[string]any{"confirm": bad}, nil); st != 422 {
			t.Fatalf("confirm %q: %d, want 422", bad, st)
		}
	}
	if _, b := h.do("GET", "/api/v1/auth/session", nil, nil); b["master_key_pending"] != true {
		t.Fatal("wrong confirmations must not release the gate")
	}
	if st, _ := h.do("POST", "/api/v1/security/master-key/acknowledge", map[string]any{"confirm": strings.ToUpper(keyHex[len(keyHex)-6:])}, nil); st != 204 {
		t.Fatalf("confirm with the last six characters: %d", st)
	}

	// Saved: the gate opens, the key is never shown again, and it was audited with the key id (never the key).
	if st, _ := h.do("GET", "/api/v1/devices", nil, nil); st != 200 {
		t.Fatalf("after confirming: %d", st)
	}
	if _, b := h.do("GET", "/api/v1/auth/session", nil, nil); b["master_key_pending"] != false {
		t.Fatalf("session after confirming: %v", b)
	}
	if st, _ := h.do("GET", "/api/v1/security/master-key", nil, nil); st != 404 {
		t.Fatalf("the key must not be shown after it was saved: %d", st)
	}
	if st, _ := h.do("POST", "/api/v1/security/master-key/acknowledge", map[string]any{"confirm": keyHex[len(keyHex)-6:]}, nil); st != 404 {
		t.Fatalf("confirming twice: %d", st)
	}
	if d := h.auditDetails("master_key.acknowledge"); d["key_id"] == nil || strings.Contains(strings.ToLower(toString(d)), keyHex[:16]) {
		t.Fatalf("audit details: %v", d)
	}
}

// A stack whose key was supplied by hand has no record and never shows the screen.
func TestNoMasterKeyScreenWhenTheKeyWasSuppliedByHand(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	if _, b := h.do("GET", "/api/v1/auth/session", nil, nil); b["master_key_pending"] != false {
		t.Fatalf("session: %v", b)
	}
	if st, _ := h.do("GET", "/api/v1/security/master-key", nil, nil); st != 404 {
		t.Fatalf("nothing to show: %d", st)
	}
	if st, _ := h.do("GET", "/api/v1/devices", nil, nil); st != 200 {
		t.Fatalf("devices: %d", st)
	}
}
