package e2e

import (
	"context"
	"testing"
)

// A token that can no longer enroll anything can be deleted; one that still can must be revoked first;
// devices that enrolled with it stay (D106).
func TestDeleteEnrollmentToken(t *testing.T) {
	h := newHarness(t)
	h.setupAndLogin()
	operator := h.orgUser("op@example.com", "operator")

	tokenIDs := func() map[string]string { // name -> id
		_, b := h.do("GET", "/api/v1/enrollment-tokens", nil, nil)
		out := map[string]string{}
		for _, it := range items(b) {
			out[it["name"].(string)] = it["id"].(string)
		}
		return out
	}

	// A token with a device behind it.
	ta := h.startAgent(h.createToken("rollout", 5, false), &fakeHW{host: "LAP-T1", serial: "ST1", uuid: "UT1"}, nil)
	waitFor(t, agentConnectWait, "agent connected", func() bool { return ta.state() == "connected" })
	h.createToken("unused", 3, false)
	ids := tokenIDs()
	if len(ids) != 2 {
		t.Fatalf("tokens: %v", ids)
	}

	// Still usable: refused, and nothing is audited.
	if st, b := h.do("DELETE", "/api/v1/enrollment-tokens/"+ids["unused"], nil, nil); st != 409 {
		t.Fatalf("deleting an active token: %d %v", st, b)
	}
	if len(tokenIDs()) != 2 {
		t.Fatal("a refused delete removed something")
	}

	// Revoke it, then only administrators may delete it.
	if st, _ := h.do("POST", "/api/v1/enrollment-tokens/"+ids["unused"]+"/revoke", map[string]any{}, nil); st != 204 {
		t.Fatalf("revoke: %d", st)
	}
	if st, _, _ := operator.raw("DELETE", "/api/v1/enrollment-tokens/"+ids["unused"], "", nil); st != 403 {
		t.Fatalf("operator delete: %d, want 403", st)
	}
	if st, b := h.do("DELETE", "/api/v1/enrollment-tokens/"+ids["unused"], nil, nil); st != 204 {
		t.Fatalf("delete revoked token: %d %v", st, b)
	}
	if _, still := tokenIDs()["unused"]; still {
		t.Fatal("the deleted token is still listed")
	}
	if st, _ := h.do("DELETE", "/api/v1/enrollment-tokens/"+ids["unused"], nil, nil); st != 404 {
		t.Fatalf("deleting it again: %d, want 404", st)
	}
	if d := h.auditDetails("enrollment_token.delete"); d["name"] != "unused" || d["state"] != "revoked" {
		t.Fatalf("audit details: %v", d)
	}

	// The token the device enrolled with: revoke and delete it; the device stays.
	if st, _ := h.do("POST", "/api/v1/enrollment-tokens/"+ids["rollout"]+"/revoke", map[string]any{}, nil); st != 204 {
		t.Fatalf("revoke: %d", st)
	}
	if st, b := h.do("DELETE", "/api/v1/enrollment-tokens/"+ids["rollout"], nil, nil); st != 204 {
		t.Fatalf("delete the token of an enrolled device: %d %v", st, b)
	}
	if devs := h.devices(); len(devs) != 1 || devs[0]["hostname"] != "LAP-T1" {
		t.Fatalf("the enrolled device must stay: %v", devs)
	}
	var via *string
	if err := h.db.Pool.QueryRow(context.Background(), `SELECT enrolled_via::text FROM devices LIMIT 1`).Scan(&via); err != nil || via != nil {
		t.Fatalf("enrolled_via after deleting the token: %v %v", via, err)
	}

	// An expired token is as dead as a revoked one.
	h.createToken("short", 2, false)
	id := tokenIDs()["short"]
	if _, err := h.db.Pool.Exec(context.Background(), `UPDATE enrollment_tokens SET expires_at = now() - interval '1 minute' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if st, b := h.do("DELETE", "/api/v1/enrollment-tokens/"+id, nil, nil); st != 204 {
		t.Fatalf("delete expired token: %d %v", st, b)
	}
}
