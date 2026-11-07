package deploy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

func (f *fixture) hardware(id uuid.UUID, ifaces ...map[string]any) {
	raw, _ := json.Marshal(map[string]any{"interfaces": ifaces})
	f.exec("UPDATE devices SET hardware = $2, online = true WHERE id = $1", id, raw)
}

func lan(name, addr, cidr string) map[string]any {
	return map[string]any{"name": name, "mac": "aa:bb:cc:00:00:01", "addresses": []string{addr}, "cidrs": []string{cidr}}
}

// redispatch offers the pending job of a device again, as happens when it reconnects.
func (f *fixture) redispatch(dev uuid.UUID) {
	f.exec("UPDATE jobs SET status = 'queued' WHERE device_id = $1", dev)
	f.svc.Dispatch(context.Background(), dev)
}

// offered returns the sources of the install job last offered to a device.
func (f *fixture) offered(dev uuid.UUID) []*agentv1.ContentSource {
	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()
	offers := f.rec.offers[dev]
	if len(offers) == 0 {
		f.t.Fatal("nothing was offered")
	}
	var env agentv1.JobEnvelope
	if err := proto.Unmarshal(offers[len(offers)-1].Payload, &env); err != nil {
		f.t.Fatal(err)
	}
	return env.GetInstall().GetInstaller().GetSources()
}

func TestPeersAreOfferedOnlyWhenTheOrganizationSharesAndTheyHaveTheFile(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	enabled := false
	f.svc.PeerCache = func(context.Context, uuid.UUID) bool { return enabled }
	target := f.device("target", "amd64")
	same := f.device("same-lan", "amd64")
	far := f.device("other-lan", "amd64")
	idle := f.device("no-file", "amd64")
	f.hardware(target, lan("Ethernet", "192.168.7.50", "192.168.7.50/24"))
	f.hardware(same, lan("Ethernet", "192.168.7.20", "192.168.7.20/24"))
	f.hardware(far, lan("Ethernet", "10.1.0.5", "10.1.0.5/24"))
	f.hardware(idle, lan("Ethernet", "192.168.7.21", "192.168.7.21/24"))
	for _, d := range []uuid.UUID{same, far, idle} {
		f.exec("UPDATE devices SET peer_port = 7421 WHERE id = $1", d)
	}
	f.rec.setOnline(target)

	// First install: nobody has the file yet, and sharing is off.
	plan, err := f.create(Request{Name: "one", Action: "install", Version: "2.0", Scope: "machine", DeviceIDs: []uuid.UUID{target}})
	if err != nil {
		t.Fatal(err)
	}
	base := len(f.offered(target))
	if base != 1 {
		t.Fatalf("a job with a single source keeps it: %d", base)
	}
	// "same", "far" and "idle" install from that file (the server learns it from their reports).
	jobs := f.jobs(plan.DeploymentID)
	sha := envOf(t, jobs[0]).GetInstall().Installer.Sha256
	for _, d := range []uuid.UUID{same, far} {
		f.exec("INSERT INTO peer_content (device_id, sha256, seen_at) VALUES ($1,$2,now())", d, sha)
	}

	// Sharing off: still no peers. On: only the online sharing device on the same network.
	f.redispatch(target)
	if got := f.offered(target); len(got) != 1 {
		t.Fatalf("sharing is off: %+v", got)
	}
	enabled = true
	f.redispatch(target)
	got := f.offered(target)
	if len(got) != 2 || got[0].Kind != agentv1.ContentSourceKind_CONTENT_SOURCE_KIND_PEER || got[0].Url != "https://192.168.7.20:7421" {
		t.Fatalf("one peer on the same network, in front of the usual source: %+v", got)
	}
	// The stored job keeps only its own sources: peers are chosen again every time it is offered.
	if n := len(envOf(t, f.jobs(plan.DeploymentID)[0]).GetInstall().Installer.Sources); n != 1 {
		t.Fatalf("the stored job was changed: %d sources", n)
	}
	// A peer that went offline, stopped sharing or has not got the file is not offered.
	f.exec("UPDATE devices SET online = false WHERE id = $1", same)
	f.redispatch(target)
	if got := f.offered(target); len(got) != 1 {
		t.Fatalf("an offline peer was offered: %+v", got)
	}
}

func TestADeviceThatFinishedAnInstallBecomesAPeerForThatFile(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	dev := f.device("pc", "amd64")
	f.rec.setOnline(dev)
	d, err := dbq.New(f.pool).GetDevice(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	run := func(name string, final agentv1.JobState) {
		plan, err := f.create(Request{Name: name, Action: "install", Version: "2.0", Scope: "machine", DeviceIDs: []uuid.UUID{dev}})
		if err != nil {
			t.Fatal(err)
		}
		id := f.jobs(plan.DeploymentID)[0].ID.String()
		for _, st := range []agentv1.JobState{agentv1.JobState_JOB_STATE_ACCEPTED, agentv1.JobState_JOB_STATE_RUNNING, final} {
			if err := f.svc.ApplyUpdate(context.Background(), d, &agentv1.JobUpdate{JobId: id, Attempt: 1, State: st, Result: &agentv1.JobResult{}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	count := func() (n int) {
		_ = f.pool.QueryRow(context.Background(), "SELECT count(*) FROM peer_content WHERE device_id = $1", dev).Scan(&n)
		return
	}
	run("fails", agentv1.JobState_JOB_STATE_FAILED)
	if count() != 0 {
		t.Fatal("a failed install must not make a peer")
	}
	run("works", agentv1.JobState_JOB_STATE_SUCCEEDED)
	if count() != 1 {
		t.Fatalf("a finished install makes the device a peer: %d", count())
	}
	run("again", agentv1.JobState_JOB_STATE_SUCCEEDED)
	if count() != 1 {
		t.Fatalf("the same file twice is one row: %d", count())
	}
}
