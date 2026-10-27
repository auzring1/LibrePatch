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
	_, ro, err := f.svc.List(context.Background(), f.org)
	if err != nil {
		f.t.Fatal(err)
	}
	if ro.ReleaseID == nil {
		return "", false
	}
	rels, _, _ := f.svc.List(context.Background(), f.org)
	for _, r := range rels {
		if r.ID == *ro.ReleaseID {
			return r.Version, true
		}
	}
	return "", false
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
	if _, ok := f.target(); ok {
		t.Fatal("without the automatic option nothing becomes the target")
	}

	// A restart (and the next minute) adds nothing again.
	f.svc.SyncBundled(ctx)
	f.svc.bd = bundledState{}
	f.svc.SyncBundled(ctx)
	if n := f.count("SELECT count(*) FROM agent_releases WHERE org_id=$1", f.org); n != 1 {
		t.Fatalf("%d releases after restarts", n)
	}
}

func TestBundledReleaseBecomesTheTargetOnlyWhenAskedAndNewer(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	old := f.addRelease("1.0.0")
	f.rollout(old, func(ro *Rollout) { ro.AutoNewRelease = true; ro.SoakHours = 7; ro.Paused = true })

	f.shipped("2.0.0", f.priv)
	f.svc.SyncBundled(ctx)
	if v, ok := f.target(); !ok || v != "2.0.0" {
		t.Fatalf("target %q %v, want 2.0.0", v, ok)
	}
	_, ro, _ := f.svc.List(ctx, f.org)
	if ro.SoakHours != 7 || !ro.Paused || !ro.AutoNewRelease {
		t.Fatalf("the rollout's other settings stay as they were (a paused rollout stays paused): %+v", ro)
	}
	if n := f.count("SELECT count(*) FROM audit_log WHERE org_id=$1 AND action='agent.rollout_set' AND actor_type='system'", f.org); n != 1 {
		t.Fatalf("selecting it is audited: %d", n)
	}

	// An administrator moves back to 1.0.0 on purpose: a restart with the same image does not undo that.
	f.rollout(old, func(ro *Rollout) { ro.AutoNewRelease = true })
	f.svc.bd = bundledState{}
	f.svc.SyncBundled(ctx)
	if v, _ := f.target(); v != "1.0.0" {
		t.Fatalf("an earlier choice was overridden: %s", v)
	}

	// An image that carries an older agent than the target changes nothing.
	f.rollout(f.addRelease("3.0.0"), func(ro *Rollout) { ro.AutoNewRelease = true })
	f.shipped("2.5.0", f.priv)
	f.svc.SyncBundled(ctx)
	if v, _ := f.target(); v != "3.0.0" {
		t.Fatalf("a release older than the target became the target: %s", v)
	}

	// Switched off: a newer release is registered but not chosen.
	f.rollout(f.addRelease("3.1.0"), func(ro *Rollout) { ro.AutoNewRelease = false })
	f.shipped("4.0.0", f.priv)
	f.svc.SyncBundled(ctx)
	if v, _ := f.target(); v != "3.1.0" {
		t.Fatalf("target changed although the option is off: %s", v)
	}
	if n := f.count("SELECT count(*) FROM agent_releases WHERE org_id=$1 AND version='4.0.0'", f.org); n != 1 {
		t.Fatal("it should still be registered, ready to choose")
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
