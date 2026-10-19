package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/settings"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

func TestRestartPendingWithoutSettings(t *testing.T) {
	g := &Gateway{}
	ctx := context.Background()
	org := uuid.New()
	if g.restartPending(ctx, org, false, true) {
		t.Fatal("queued deletions must not count when no setting says so")
	}
	if !g.restartPending(ctx, org, true, false) {
		t.Fatal("what the agent says Windows needs always counts")
	}
	if g.restartPending(ctx, org, false, false) {
		t.Fatal("nothing pending")
	}
}

func TestRestartPendingFollowsTheDeviceDefaultsSetting(t *testing.T) {
	db := pgtest.New(t)
	ctx := context.Background()
	org, user := uuid.New(), uuid.New()
	if _, err := db.Pool.Exec(ctx, "INSERT INTO organizations (id, name) VALUES ($1, 'o')", org); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Pool.Exec(ctx, "INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, 'a@example.com', 'A', 'x')", user, org); err != nil {
		t.Fatal(err)
	}
	svc := &settings.Service{Pool: db.Pool}
	g := &Gateway{settings: svc}

	// The default is off: Edge and Firefox leftovers queued for deletion do not make a PC "restart pending".
	if g.restartPending(ctx, org, false, true) {
		t.Fatal("queued deletions counted by default")
	}
	if _, err := svc.Put(ctx, settings.Actor{Org: org, User: user}, "devices", 0, map[string]any{"queued_deletes_need_restart": true}); err != nil {
		t.Fatal(err)
	}
	if !g.restartPending(ctx, org, false, true) {
		t.Fatal("queued deletions must count once the setting is on")
	}
	if g.restartPending(ctx, org, false, false) {
		t.Fatal("no queued deletions, nothing pending, whatever the setting")
	}
	// Another organization is unaffected.
	if g.restartPending(ctx, uuid.New(), false, true) {
		t.Fatal("the setting leaked to another organization")
	}
}

func TestValidateHardwareBoundsQueuedFiles(t *testing.T) {
	ok := &agentv1.HardwareInventory{QueuedFileDeleteCount: 40, QueuedFileDeletes: []string{`C:\Temp\a`}}
	if err := validateHardware(ok); err != nil {
		t.Fatal(err)
	}
	tooMany := &agentv1.HardwareInventory{QueuedFileDeletes: make([]string, 17)}
	if validateHardware(tooMany) == nil {
		t.Fatal("more than 16 samples accepted")
	}
	tooLong := &agentv1.HardwareInventory{QueuedFileDeletes: []string{strings.Repeat("x", 1025)}}
	if validateHardware(tooLong) == nil {
		t.Fatal("a 1025 character path accepted")
	}
}

func TestFreeBytesIsUnknownUntilReported(t *testing.T) {
	if freeBytes(&agentv1.Heartbeat{}) != nil {
		t.Fatal("zero must be stored as unknown, not as a full disk")
	}
	if v := freeBytes(&agentv1.Heartbeat{SystemDriveFreeBytes: 5 << 30}); v == nil || *v != 5<<30 {
		t.Fatalf("got %v", v)
	}
	if v := freeBytes(&agentv1.Heartbeat{SystemDriveFreeBytes: ^uint64(0)}); v == nil || *v <= 0 {
		t.Fatalf("an out-of-range value must be clamped, got %v", v)
	}
}
