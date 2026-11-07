package agentrel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// shipped writes the two files the server image carries into a new directory and points the service at it.
func (f *fx) shipped(version string, key ed25519.PrivateKey) {
	f.t.Helper()
	dir := f.t.TempDir()
	bin := []byte("MZ agent " + version)
	base := filepath.Join(dir, "librepatch-agent_"+version+"_windows_amd64")
	if err := os.WriteFile(base+".exe", bin, 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(base+".lprel", f.bundle(version, bin, key), 0o600); err != nil {
		f.t.Fatal(err)
	}
	f.svc.BundledDir = dir
	f.svc.bd = bundledState{} // as after a restart
}

func (f *fx) target() (string, bool) {
	f.t.Helper()
	var v string
	err := f.pool.QueryRow(context.Background(), "SELECT r.version FROM agent_rollout o JOIN agent_releases r ON r.id = o.release_id WHERE o.org_id=$1", f.org).Scan(&v)
	return v, err == nil
}

func TestBundledReleaseIsRegisteredByTheServer(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	f.shipped("2.0.0", f.priv)

	f.svc.SyncBundled(ctx)
	if n := f.count("SELECT count(*) FROM agent_releases WHERE org_id=$1 AND version='2.0.0' AND uploaded_by IS NULL", f.org); n != 1 {
		t.Fatalf("the release should be registered once, without a person as uploader: %d", n)
	}
	if n := f.count("SELECT count(*) FROM audit_log WHERE org_id=$1 AND action='agent.release_add' AND actor_type='system'", f.org); n != 1 {
		t.Fatalf("registering it is audited as the system: %d", n)
	}
	if v, ok := f.target(); !ok || v != "2.0.0" {
		t.Fatalf("the release from the image becomes the target by itself: %q %v", v, ok)
	}

	// A restart (and the next minute) adds nothing again.
	f.svc.SyncBundled(ctx)
	f.svc.bd = bundledState{}
	f.svc.SyncBundled(ctx)
	if n := f.count("SELECT count(*) FROM agent_releases WHERE org_id=$1", f.org); n != 1 {
		t.Fatalf("%d releases after restarts", n)
	}
}

func TestBundledReleaseBecomesTheTargetWhenNewer(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()

	// No rollout row yet (a fresh installation): the image's release becomes the target by itself.
	f.shipped("1.5.0", f.priv)
	f.svc.SyncBundled(ctx)
	if v, ok := f.target(); !ok || v != "1.5.0" {
		t.Fatalf("target %q %v, want 1.5.0", v, ok)
	}
	if n := f.count("SELECT count(*) FROM audit_log WHERE org_id=$1 AND action='agent.rollout_set' AND actor_type='system'", f.org); n != 1 {
		t.Fatalf("selecting it is audited: %d", n)
	}

	// A newer image takes over; an administrator's pause and the other settings stay.
	f.exec("UPDATE agent_rollout SET paused=true, paused_reason='paused by an administrator', soak_hours=7 WHERE org_id=$1", f.org)
	f.shipped("2.0.0", f.priv)
	f.svc.SyncBundled(ctx)
	if v, _ := f.target(); v != "2.0.0" {
		t.Fatalf("target %s, want 2.0.0", v)
	}
	var paused bool
	var soak int32
	f.pool.QueryRow(ctx, "SELECT paused, soak_hours FROM agent_rollout WHERE org_id=$1", f.org).Scan(&paused, &soak)
	if !paused || soak != 7 {
		t.Fatalf("paused=%v soak=%d", paused, soak)
	}

	// Restarting with the same image changes nothing, and an older image never moves the target backwards.
	f.svc.bd = bundledState{}
	f.svc.SyncBundled(ctx)
	f.shipped("1.9.0", f.priv)
	f.svc.SyncBundled(ctx)
	if v, _ := f.target(); v != "2.0.0" {
		t.Fatalf("target moved to %s", v)
	}
	if n := f.count("SELECT count(*) FROM audit_log WHERE org_id=$1 AND action='agent.rollout_set'", f.org); n != 2 {
		t.Fatalf("%d target changes audited, want 2", n)
	}
}

func TestBundledReleaseNeedsATrustedKeyAndItsFile(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	f.shipped("2.0.0", other)
	f.svc.SyncBundled(ctx)
	if n := f.count("SELECT count(*) FROM agent_releases WHERE org_id=$1", f.org); n != 0 {
		t.Fatal("a release signed with a key the server does not trust must not be registered")
	}

	f.shipped("2.0.0", f.priv)
	if err := os.Remove(filepath.Join(f.svc.BundledDir, "librepatch-agent_2.0.0_windows_amd64.exe")); err != nil {
		t.Fatal(err)
	}
	f.svc.SyncBundled(ctx)
	if n := f.count("SELECT count(*) FROM agent_releases WHERE org_id=$1", f.org); n != 0 {
		t.Fatal("an update file without its executable must not be registered")
	}

	// No directory configured (a development server): nothing happens.
	f.svc.BundledDir = ""
	f.svc.bd = bundledState{}
	f.svc.SyncBundled(ctx)
}
