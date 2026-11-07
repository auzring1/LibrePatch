package jobs

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
)

type sentPacket struct {
	local net.IP
	dest  string
	pkt   []byte
}

func wakeRig(t *testing.T, nets ...string) (*rig, *[]sentPacket) {
	r := newRig(t)
	r.e.Sleep = func(_ context.Context, d time.Duration) { r.now = r.now.Add(d) }
	var mu sync.Mutex
	var sent []sentPacket
	r.e.LocalNets = func() []LocalNet {
		var out []LocalNet
		for _, c := range nets {
			ip, n, _ := net.ParseCIDR(c)
			out = append(out, LocalNet{IP: ip.To4(), Net: n})
		}
		return out
	}
	r.e.SendUDP = func(local net.IP, dest string, pkt []byte) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, sentPacket{local, dest, append([]byte(nil), pkt...)})
		return nil
	}
	return r, &sent
}

func wakeEnv(r *rig, id string, targets ...*agentv1.WakeTarget) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
	env := &agentv1.JobEnvelope{Version: 1, JobId: id, OrgId: "o", DeviceId: "d", Type: agentv1.JobType_JOB_TYPE_WAKE,
		IssuedAt: r.now.Unix(), NotBefore: r.now.Unix(), ExpiresAt: r.now.Add(time.Hour).Unix(), Nonce: make([]byte, 16),
		Body: &agentv1.JobEnvelope_Wake{Wake: &agentv1.WakeBody{Targets: targets}}}
	return r.sign(env), env
}

func TestWakeSendsTheMagicPacketOnTheMatchingNetworkOnly(t *testing.T) {
	r, sent := wakeRig(t, "10.1.0.5/24", "192.168.7.20/24")
	se, env := wakeEnv(r, "w1", &agentv1.WakeTarget{Mac: "AA:BB:CC:00:11:22", LastIp: "192.168.7.99"})
	r.e.Accept(se, env)
	r.tick()
	if r.state("w1") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("%v %+v", r.state("w1"), r.rec.last("w1"))
	}
	if len(*sent) == 0 {
		t.Fatal("nothing was sent")
	}
	mac := []byte{0xaa, 0xbb, 0xcc, 0x00, 0x11, 0x22}
	for _, p := range *sent {
		if !p.local.Equal(net.IPv4(192, 168, 7, 20)) || (p.dest != "192.168.7.255:9" && p.dest != "255.255.255.255:9") {
			t.Fatalf("a packet left the wrong way: %s from %s", p.dest, p.local)
		}
		if len(p.pkt) != 102 || string(p.pkt[:6]) != "\xff\xff\xff\xff\xff\xff" || string(p.pkt[6:12]) != string(mac) || string(p.pkt[96:102]) != string(mac) {
			t.Fatalf("not a magic packet: %x", p.pkt)
		}
	}
}

func TestWakeRefusesAComputerOnAnotherNetwork(t *testing.T) {
	r, sent := wakeRig(t, "10.1.0.5/24")
	se, env := wakeEnv(r, "w1", &agentv1.WakeTarget{Mac: "aa:bb:cc:00:11:22", LastIp: "172.16.4.9"})
	r.e.Accept(se, env)
	r.tick()
	u := r.rec.last("w1")
	if u.State != agentv1.JobState_JOB_STATE_FAILED || u.Reason != "wrong_network" || len(*sent) != 0 {
		t.Fatalf("%v %q sent=%d", u.State, u.Reason, len(*sent))
	}
}

func TestWakeWithSeveralCardsReportsWhichOnesWereReachable(t *testing.T) {
	r, sent := wakeRig(t, "10.1.0.5/16")
	se, env := wakeEnv(r, "w1", &agentv1.WakeTarget{Mac: "aa:bb:cc:00:11:22", LastIp: "10.1.4.4"}, &agentv1.WakeTarget{Mac: "aa:bb:cc:00:11:33", LastIp: "192.168.0.4"})
	r.e.Accept(se, env)
	r.tick()
	if r.state("w1") != agentv1.JobState_JOB_STATE_SUCCEEDED || !strings.Contains(r.rec.last("w1").Result.Message, "not on this network: aa:bb:cc:00:11:33") || len(*sent) == 0 {
		t.Fatalf("%v %q", r.state("w1"), r.rec.last("w1").Result.Message)
	}
}

func TestWakeBodiesAreValidated(t *testing.T) {
	good := &agentv1.WakeTarget{Mac: "aa:bb:cc:00:11:22", LastIp: "10.0.0.2"}
	if err := ValidateWake(&agentv1.WakeBody{Targets: []*agentv1.WakeTarget{good}}); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]*agentv1.WakeBody{
		"nil":          nil,
		"none":         {},
		"five":         {Targets: []*agentv1.WakeTarget{good, good, good, good, good}},
		"short mac":    {Targets: []*agentv1.WakeTarget{{Mac: "aa:bb:cc", LastIp: "10.0.0.2"}}},
		"broadcast":    {Targets: []*agentv1.WakeTarget{{Mac: "ff:ff:ff:ff:ff:ff", LastIp: "10.0.0.2"}}},
		"multicast":    {Targets: []*agentv1.WakeTarget{{Mac: "01:00:5e:00:00:01", LastIp: "10.0.0.2"}}},
		"zero":         {Targets: []*agentv1.WakeTarget{{Mac: "00:00:00:00:00:00", LastIp: "10.0.0.2"}}},
		"no address":   {Targets: []*agentv1.WakeTarget{{Mac: "aa:bb:cc:00:11:22"}}},
		"ipv6":         {Targets: []*agentv1.WakeTarget{{Mac: "aa:bb:cc:00:11:22", LastIp: "fe80::1"}}},
		"multicast ip": {Targets: []*agentv1.WakeTarget{{Mac: "aa:bb:cc:00:11:22", LastIp: "224.0.0.1"}}},
	} {
		if err := ValidateWake(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func inspectEnv(r *rig, id string, b *agentv1.InspectBody) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
	env := &agentv1.JobEnvelope{Version: 1, JobId: id, OrgId: "o", DeviceId: "d", Type: agentv1.JobType_JOB_TYPE_INSPECT,
		IssuedAt: r.now.Unix(), NotBefore: r.now.Unix(), ExpiresAt: r.now.Add(time.Hour).Unix(), Nonce: make([]byte, 16),
		Body: &agentv1.JobEnvelope_Inspect{Inspect: b}}
	return r.sign(env), env
}

func TestInspectProcessesReturnsSortedJSON(t *testing.T) {
	r := newRig(t)
	r.p.psList = []ProcessInfo{{PID: 9, Name: "zeta.exe"}, {PID: 4, Name: "Alpha.exe", WorkingSetKB: 2048}, {PID: 2, Name: "alpha.exe"}}
	se, env := inspectEnv(r, "i1", &agentv1.InspectBody{Kind: agentv1.InspectKind_INSPECT_KIND_PROCESSES})
	r.e.Accept(se, env)
	r.tick()
	res := r.rec.last("i1").Result
	if r.state("i1") != agentv1.JobState_JOB_STATE_SUCCEEDED || res.DataJson == "" {
		t.Fatalf("%v %+v", r.state("i1"), res)
	}
	var doc struct {
		Kind      string        `json:"kind"`
		Truncated bool          `json:"truncated"`
		Items     []ProcessInfo `json:"items"`
	}
	if err := json.Unmarshal([]byte(res.DataJson), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Kind != "processes" || doc.Truncated || len(doc.Items) != 3 || doc.Items[0].PID != 2 || doc.Items[1].PID != 4 || doc.Items[2].Name != "zeta.exe" {
		t.Fatalf("%+v", doc)
	}
}

func TestInspectViewsAreSizeCapped(t *testing.T) {
	r := newRig(t)
	var ps []ProcessInfo
	for i := 0; i < 4000; i++ {
		ps = append(ps, ProcessInfo{PID: uint32(i), Name: "p.exe", Path: strings.Repeat("x", 200)})
	}
	r.p.psList = ps
	se, env := inspectEnv(r, "i1", &agentv1.InspectBody{Kind: agentv1.InspectKind_INSPECT_KIND_PROCESSES})
	r.e.Accept(se, env)
	r.tick()
	res := r.rec.last("i1").Result
	if len(res.DataJson) > MaxInspectBytes || !strings.Contains(res.DataJson, `"truncated":true`) || !strings.Contains(res.Message, "shortened") {
		t.Fatalf("len=%d msg=%q", len(res.DataJson), res.Message)
	}
}

func TestInspectEventsUseDefaultsAndClipMessages(t *testing.T) {
	r := newRig(t)
	r.p.eventList = []EventInfo{{Time: 100, Level: 2, Provider: "Disk", ID: 7, Message: strings.Repeat("é", 2000)}}
	se, env := inspectEnv(r, "i1", &agentv1.InspectBody{Kind: agentv1.InspectKind_INSPECT_KIND_EVENTS})
	r.e.Accept(se, env)
	r.tick()
	if len(r.p.eventQ) != 1 || r.p.eventQ[0].Log != "System" || r.p.eventQ[0].MaxLevel != 3 || r.p.eventQ[0].Since != 24*time.Hour || r.p.eventQ[0].Max != 100 {
		t.Fatalf("defaults: %+v", r.p.eventQ)
	}
	var doc struct{ Items []EventInfo }
	_ = json.Unmarshal([]byte(r.rec.last("i1").Result.DataJson), &doc)
	if len(doc.Items) != 1 || len(doc.Items[0].Message) > maxEventMessage+4 || !strings.HasSuffix(doc.Items[0].Message, "…") {
		t.Fatalf("message not clipped: %d", len(doc.Items[0].Message))
	}
}

func TestInspectOnAnUnsupportedPlatformFailsPlainly(t *testing.T) {
	r := newRig(t)
	r.p.viewErr = ErrUnsupported
	se, env := inspectEnv(r, "i1", &agentv1.InspectBody{Kind: agentv1.InspectKind_INSPECT_KIND_SERVICES})
	r.e.Accept(se, env)
	r.tick()
	if r.state("i1") != agentv1.JobState_JOB_STATE_FAILED {
		t.Fatal(r.state("i1"))
	}
}

func TestInspectBodiesAreValidatedAndTheSecurityLogIsNeverOffered(t *testing.T) {
	ev := agentv1.InspectKind_INSPECT_KIND_EVENTS
	for name, b := range map[string]*agentv1.InspectBody{
		"nil": nil, "no kind": {}, "security log": {Kind: ev, Log: "Security"}, "other log": {Kind: ev, Log: "Microsoft-Windows-PowerShell/Operational"},
		"level": {Kind: ev, MaxLevel: 9}, "since": {Kind: ev, SinceMinutes: 20000}, "count": {Kind: ev, MaxEvents: 500},
	} {
		if err := ValidateInspect(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for _, b := range []*agentv1.InspectBody{{Kind: ev, Log: "Application", MaxLevel: 2, SinceMinutes: 60, MaxEvents: 50}, {Kind: ev},
		{Kind: agentv1.InspectKind_INSPECT_KIND_PROCESSES}, {Kind: agentv1.InspectKind_INSPECT_KIND_SERVICES}} {
		if err := ValidateInspect(b); err != nil {
			t.Errorf("%+v: %v", b, err)
		}
	}
}

func TestInspectAndWakeAreCoveredByTheLocalCeiling(t *testing.T) {
	r := newRig(t)
	r.e.Allowed = map[string]bool{"inventory": true}
	se, env := inspectEnv(r, "i1", &agentv1.InspectBody{Kind: agentv1.InspectKind_INSPECT_KIND_PROCESSES})
	r.e.Accept(se, env)
	se, env = wakeEnv(r, "w1", &agentv1.WakeTarget{Mac: "aa:bb:cc:00:11:22", LastIp: "10.0.0.2"})
	r.e.Accept(se, env)
	if r.state("i1") != agentv1.JobState_JOB_STATE_REJECTED || r.state("w1") != agentv1.JobState_JOB_STATE_REJECTED {
		t.Fatalf("%v %v", r.state("i1"), r.state("w1"))
	}
}

const sampleEvents = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='disk'/><EventID Qualifiers='49156'>7</EventID><Level>2</Level><TimeCreated SystemTime='2026-10-20T08:15:30.1234567Z'/></System><EventData><Data>\Device\Harddisk0\DR0</Data></EventData><RenderingInfo Culture='en-US'><Message>The device, \Device\Harddisk0\DR0, has a bad block.</Message></RenderingInfo></Event>
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID>7036</EventID><Level>3</Level><TimeCreated SystemTime='2026-10-20T08:10:00.000Z'/></System><EventData><Data Name='param1'>Print Spooler</Data><Data Name='param2'>stopped</Data></EventData></Event>`

func TestParseEventXML(t *testing.T) {
	evs, err := ParseEventXML(strings.NewReader(sampleEvents), 10)
	if err != nil || len(evs) != 2 {
		t.Fatalf("%v %+v", err, evs)
	}
	if evs[0].Provider != "disk" || evs[0].ID != 7 || evs[0].Level != 2 || !strings.Contains(evs[0].Message, "bad block") || time.Unix(evs[0].Time, 0).UTC().Format("15:04:05") != "08:15:30" {
		t.Fatalf("%+v", evs[0])
	}
	if evs[1].Message != "Print Spooler | stopped" {
		t.Fatalf("the data is used when there is no rendered message: %+v", evs[1])
	}
	if one, _ := ParseEventXML(strings.NewReader(sampleEvents), 1); len(one) != 1 {
		t.Fatal("the limit is honoured")
	}
	if none, err := ParseEventXML(strings.NewReader(""), 5); err != nil || len(none) != 0 {
		t.Fatalf("empty output: %v %v", err, none)
	}
}

// A read-only view and a wake-up packet must not wait behind a long job (a scan, an installer).
func TestViewsAndWakeRunOnTheControlLaneWhileAScanIsRunning(t *testing.T) {
	r, sent := wakeRig(t, "192.168.7.20/24")
	r.p.wuc.scanGate, r.p.wuc.scanning = make(chan struct{}), make(chan struct{}, 1)
	r.p.psList = []ProcessInfo{{PID: 1, Name: "a.exe"}}
	r.e.init()
	scan, scanEnv := r.wuEnv("scan", agentv1.JobType_JOB_TYPE_WU_SCAN, nil)
	r.e.Accept(scan, scanEnv)
	done := make(chan struct{})
	go func() { r.e.tickLane(r.ctx, laneScan); close(done) }()
	select {
	case <-r.p.wuc.scanning:
	case <-time.After(5 * time.Second):
		t.Fatal("the scan never started")
	}
	se, env := inspectEnv(r, "i1", &agentv1.InspectBody{Kind: agentv1.InspectKind_INSPECT_KIND_PROCESSES})
	r.e.Accept(se, env)
	se, env = wakeEnv(r, "w1", &agentv1.WakeTarget{Mac: "aa:bb:cc:00:11:22", LastIp: "192.168.7.99"})
	r.e.Accept(se, env)
	r.e.tickLane(r.ctx, laneControl)
	if r.state("i1") != agentv1.JobState_JOB_STATE_SUCCEEDED || r.state("w1") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(*sent) == 0 {
		t.Fatalf("view %v wake %v while the scan runs", r.state("i1"), r.state("w1"))
	}
	close(r.p.wuc.scanGate)
	<-done
}
