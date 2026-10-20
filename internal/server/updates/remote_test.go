package updates

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

func (f *fx) setHardware(d dbq.Device, ifaces ...map[string]any) dbq.Device {
	raw, _ := json.Marshal(map[string]any{"interfaces": ifaces})
	f.exec("UPDATE devices SET hardware = $2 WHERE id = $1", d.ID, raw)
	d.Hardware = raw
	return d
}

func nic(name, mac string, addrs, cidrs []string) map[string]any {
	return map[string]any{"name": name, "mac": mac, "addresses": addrs, "cidrs": cidrs}
}

func (f *fx) jobBody(id string) *agentv1.JobEnvelope {
	var raw []byte
	if err := f.pool.QueryRow(context.Background(), "SELECT body FROM jobs WHERE id = $1", id).Scan(&raw); err != nil {
		f.t.Fatal(err)
	}
	var env agentv1.JobEnvelope
	if err := proto.Unmarshal(raw, &env); err != nil {
		f.t.Fatal(err)
	}
	return &env
}

func TestWakeGoesThroughAnOnlineComputerOnTheSameNetwork(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	sleeper := f.setHardware(f.device("sleeper", false),
		nic("Ethernet", "AA:BB:CC:00:11:22", []string{"192.168.7.50"}, []string{"192.168.7.50/24"}),
		nic("vEthernet (Default Switch)", "00:15:5D:00:00:01", []string{"172.20.0.1"}, []string{"172.20.0.1/20"}))
	other := f.setHardware(f.device("other-net", true), nic("Ethernet", "AA:00:00:00:00:01", []string{"10.1.0.5"}, []string{"10.1.0.5/24"}))
	helper := f.setHardware(f.device("helper", true), nic("Ethernet", "AA:00:00:00:00:02", []string{"192.168.7.20"}, []string{"192.168.7.20/24"}))
	_ = other

	id, host, err := f.svc.WakeDevice(ctx, f.actor(), sleeper.ID)
	if err != nil || host != "helper" {
		t.Fatalf("%v %q", err, host)
	}
	env := f.jobBody(id.String())
	if env.Type != agentv1.JobType_JOB_TYPE_WAKE || env.DeviceId != helper.ID.String() {
		t.Fatalf("the job must go to the helper: %v %s", env.Type, env.DeviceId)
	}
	ts := env.GetWake().GetTargets()
	if len(ts) != 1 || ts[0].Mac != "aa:bb:cc:00:11:22" || ts[0].LastIp != "192.168.7.50" {
		t.Fatalf("only the real network card is woken: %+v", ts)
	}
	var target string
	if err := f.pool.QueryRow(ctx, "SELECT target_ids[1] FROM audit_log WHERE action='device.wake'").Scan(&target); err != nil || target != sleeper.ID.String() {
		t.Fatalf("the audit entry is about the sleeping device: %q %v", target, err)
	}
}

func TestWakeRefusals(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	online := f.setHardware(f.device("up", true), nic("Ethernet", "AA:BB:CC:00:11:22", []string{"10.9.0.5"}, []string{"10.9.0.5/24"}))
	if _, _, err := f.svc.WakeDevice(ctx, f.actor(), online.ID); !errors.Is(err, ErrAlreadyOnline) {
		t.Fatalf("online: %v", err)
	}
	blank := f.device("blank", false)
	if _, _, err := f.svc.WakeDevice(ctx, f.actor(), blank.ID); !errors.Is(err, ErrNoAddress) {
		t.Fatalf("no hardware: %v", err)
	}
	// An agent that does not report its networks (older version) cannot be a helper.
	sleeper := f.setHardware(f.device("sleeper", false), nic("Ethernet", "AA:BB:CC:00:11:33", []string{"192.168.7.51"}, nil))
	f.setHardware(f.device("old-agent", true), nic("Ethernet", "AA:00:00:00:00:02", []string{"192.168.7.20"}, nil))
	if _, _, err := f.svc.WakeDevice(ctx, f.actor(), sleeper.ID); !errors.Is(err, ErrNoHelper) {
		t.Fatalf("no helper: %v", err)
	}
	// A /31 or /32 is no network to broadcast on.
	f.setHardware(f.device("tiny", true), nic("Ethernet", "AA:00:00:00:00:03", []string{"192.168.7.52"}, []string{"192.168.7.52/32"}))
	if _, _, err := f.svc.WakeDevice(ctx, f.actor(), sleeper.ID); !errors.Is(err, ErrNoHelper) {
		t.Fatalf("tiny network: %v", err)
	}
}

func TestInspectJobsAndTheirPrivateData(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	off := f.device("off", false)
	if _, err := f.svc.InspectDevice(ctx, f.actor(), off.ID, InspectRequest{Kind: "processes"}); !errors.Is(err, ErrOffline) {
		t.Fatalf("offline: %v", err)
	}
	d := f.device("on", true)
	for name, r := range map[string]InspectRequest{"kind": {Kind: "registry"}, "log": {Kind: "events", Log: "Security"}, "level": {Kind: "events", MaxLevel: 9}, "count": {Kind: "events", MaxEvents: 999}} {
		if _, err := f.svc.InspectDevice(ctx, f.actor(), d.ID, r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	id, err := f.svc.InspectDevice(ctx, f.actor(), d.ID, InspectRequest{Kind: "events", Log: "Application", MaxLevel: 2, SinceMinutes: 60, MaxEvents: 20})
	if err != nil {
		t.Fatal(err)
	}
	b := f.jobBody(id.String()).GetInspect()
	if b.Kind != agentv1.InspectKind_INSPECT_KIND_EVENTS || b.Log != "Application" || b.MaxLevel != 2 || b.SinceMinutes != 60 || b.MaxEvents != 20 {
		t.Fatalf("%+v", b)
	}
	if v, err := f.svc.GetView(ctx, f.org, d.ID, id); err != nil || v.Data != nil {
		t.Fatalf("nothing before the device answers: %v %+v", err, v)
	}

	// The device answers: the data lands in its own table, not in the job result.
	data := `{"kind":"events","taken_at":1,"truncated":false,"total":1,"items":[{"time":1,"level":2,"provider":"disk","id":7,"message":"bad block"}]}`
	if err := f.dep.ApplyUpdate(ctx, d, &agentv1.JobUpdate{JobId: id.String(), Attempt: 1, State: agentv1.JobState_JOB_STATE_SUCCEEDED,
		Result: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, Message: "view read", DataJson: data}}); err != nil {
		t.Fatal(err)
	}
	v, err := f.svc.GetView(ctx, f.org, d.ID, id)
	if err != nil || v.Status != "succeeded" || v.Kind != "events" || len(v.Data) == 0 {
		t.Fatalf("%v %+v", err, v)
	}
	var result []byte
	_ = f.pool.QueryRow(ctx, "SELECT result FROM jobs WHERE id = $1", id).Scan(&result)
	if len(result) == 0 || json.Valid(result) && containsStr(string(result), "bad block") {
		t.Fatalf("the data must not be in the job result that job pages show: %s", result)
	}
	// Another device's job id, or another organization, reads nothing.
	other := f.device("other", true)
	if _, err := f.svc.GetView(ctx, f.org, other.ID, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another device: %v", err)
	}
	if _, err := f.svc.GetView(ctx, [16]byte{1}, d.ID, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another organization: %v", err)
	}
}

func TestMalformedViewDataIsDropped(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	d := f.device("on", true)
	for i, data := range []string{`not json`, `{"kind":"secrets","items":[]}`, `{"kind":"processes","items":"` + string(make([]byte, 0)) + `"` /* unterminated */} {
		id, err := f.svc.InspectDevice(ctx, f.actor(), d.ID, InspectRequest{Kind: "processes"})
		if err != nil {
			t.Fatal(err)
		}
		if err := f.dep.ApplyUpdate(ctx, d, &agentv1.JobUpdate{JobId: id.String(), Attempt: 1, State: agentv1.JobState_JOB_STATE_SUCCEEDED,
			Result: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DataJson: data}}); err != nil {
			t.Fatal(err)
		}
		if v, _ := f.svc.GetView(ctx, f.org, d.ID, id); v == nil || v.Data != nil {
			t.Errorf("case %d: bad data was kept: %+v", i, v)
		}
	}
}

func containsStr(s, sub string) bool {
	return len(sub) > 0 && (len(s) >= len(sub)) && (indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
