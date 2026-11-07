package audit

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/auzring1/librepatch/gen/dbq"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

func TestChainWriteVerifyAndImmutability(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	org := uuid.New()
	for i := 0; i < 5; i++ {
		if err := Log(ctx, db.Pool, Entry{OrgID: &org, ActorType: ActorUser, ActorID: "u1", ActorIP: "10.0.0.1",
			Action: "test.action", TargetType: "device", TargetIDs: []string{"d1"}, Outcome: Success,
			Details: map[string]any{"n": i, "nested": map[string]any{"b": "<x>", "a": true}}}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Verify(ctx, dbq.New(db.Pool))
	if err != nil || res.Checked != 5 || res.BrokenAt != 0 {
		t.Fatalf("verify: %+v %v", res, err)
	}
	// The runtime role must not be able to modify or delete audit rows.
	if _, err := db.Pool.Exec(ctx, "UPDATE audit_log SET action='x'"); err == nil {
		t.Fatal("UPDATE on audit_log must be denied")
	}
	if _, err := db.Pool.Exec(ctx, "DELETE FROM audit_log"); err == nil {
		t.Fatal("DELETE on audit_log must be denied")
	}
	if _, err := db.Pool.Exec(ctx, "TRUNCATE audit_log"); err == nil {
		t.Fatal("TRUNCATE on audit_log must be denied")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := Log(ctx, db.Pool, Entry{ActorType: ActorSystem, Action: "a", Outcome: Success}); err != nil {
			t.Fatal(err)
		}
	}
	// Simulate an attacker with owner rights who disables the trigger and edits a row.
	owner := pgtest.OwnerConn(t, db)
	for _, stmt := range []string{
		"ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete",
		"UPDATE audit_log SET action='tampered' WHERE id = (SELECT min(id)+1 FROM audit_log)",
	} {
		if _, err := owner.Exec(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Verify(ctx, dbq.New(db.Pool))
	if err != nil {
		t.Fatal(err)
	}
	if res.BrokenAt == 0 {
		t.Fatal("tampering not detected")
	}
	_ = time.Now
}
