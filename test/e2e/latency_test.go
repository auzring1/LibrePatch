//go:build !windows

// The restart probes replace the platform's Reboot (the Linux dev platform only writes a file); on Windows the real
// service would restart the machine, so these run on Linux only, like the scripted Windows Update client they use.
package e2e

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/core"
	"github.com/auzring1/librepatch/internal/agent/jobs"
	"github.com/auzring1/librepatch/internal/agent/store"
	"github.com/auzring1/librepatch/internal/agent/wu"
)

// latencyPlatform stamps the moment the agent asks the operating system to restart (the last hop before Windows
// shows its countdown).
type latencyPlatform struct {
	jobs.Platform
	rebooted  chan time.Time
	scanDelay *delay
}

func (p *latencyPlatform) WindowsUpdate() wu.Client {
	return slowWU{Client: p.Platform.WindowsUpdate(), delay: p.scanDelay}
}

// slowWU makes the Windows Update search slow, as the real Windows Update Agent often is (20 to 90 s).
type slowWU struct {
	wu.Client
	delay *delay
}

func (s slowWU) Scan(ctx context.Context, o wu.Options) ([]*agentv1.WuUpdate, error) {
	select {
	case <-time.After(s.delay.get()):
	case <-ctx.Done():
	}
	return s.Client.Scan(ctx, o)
}

func (p *latencyPlatform) Reboot(delay time.Duration, message string) error {
	select {
	case p.rebooted <- time.Now():
	default:
	}
	return p.Platform.Reboot(delay, message)
}

// delay is a duration the test can change while the agent runs.
type delay struct {
	mu sync.Mutex
	d  time.Duration
}

func (d *delay) set(v time.Duration) { d.mu.Lock(); d.d = v; d.mu.Unlock() }
func (d *delay) get() time.Duration  { d.mu.Lock(); defer d.mu.Unlock(); return d.d }

// slowHW makes the hardware collector slow on demand (a WMI BitLocker query takes seconds on a real PC and is
// abandoned only after 20 s).
type slowHW struct {
	*fakeHW
	delay *delay
}

func (h *slowHW) Collect(ctx context.Context) (*agentv1.HardwareInventory, error) {
	select {
	case <-time.After(h.delay.get()):
	case <-ctx.Done():
	}
	return h.fakeHW.Collect(ctx)
}

type hops struct {
	apiReturned time.Duration // click until the REST call returned (API, database, audit entry)
	serverSent  time.Duration // click until the server wrote the job to the device's stream
	agentOS     time.Duration // click until the agent asked Windows to restart (Reboot called)
}

// restartOnce clicks "Restart" for a device and times every hop.
func (h *harness) restartOnce(t *testing.T, dev string, rebooted <-chan time.Time) hops {
	t.Helper()
	for len(rebooted) > 0 {
		<-rebooted
	}
	t0 := time.Now()
	st, rb := h.do("POST", "/api/v1/devices/"+dev+"/reboot", map[string]any{"minutes": 1, "reason": "latency probe"}, nil)
	t1 := time.Now()
	if st != 202 {
		t.Fatalf("reboot: %d %v", st, rb)
	}
	var tOS time.Time
	select {
	case tOS = <-rebooted:
	case <-time.After(60 * time.Second):
		t.Fatal("the agent never asked the operating system to restart")
	}
	id, _ := uuid.Parse(rb["job_id"].(string))
	var sentAt *time.Time
	_ = h.db.Pool.QueryRow(context.Background(), `SELECT sent_at FROM jobs WHERE id = $1`, id).Scan(&sentAt)
	out := hops{apiReturned: t1.Sub(t0), agentOS: tOS.Sub(t0)}
	if sentAt != nil {
		out.serverSent = sentAt.Sub(t0)
	}
	return out
}

func median(d []time.Duration) time.Duration {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func latencyAgent(t *testing.T) (*harness, *testAgent, string, *latencyPlatform, *delay) {
	h := newHarness(t)
	h.setupAndLogin()
	plat := &latencyPlatform{rebooted: make(chan time.Time, 4), scanDelay: &delay{}}
	hwDelay := &delay{}
	hw := &slowHW{fakeHW: &fakeHW{host: "LAT-1", serial: "SLAT1", uuid: "ULAT1"}, delay: hwDelay}
	ta := h.startAgent(h.createToken("latency", 5, false), hw.fakeHW, nil, func(a *core.Agent, st *store.Store) {
		plat.Platform = jobs.NewPlatform(a.DataDir)
		a.Jobs = &jobs.Engine{P: plat, Store: st, Log: a.Log}
		a.HW = hw
	})
	waitFor(t, 20*time.Second, "agent connected", func() bool { return ta.state() == "connected" })
	dev := h.devices()[0]["id"].(string)
	// Let the first inventory exchange and the first heartbeat settle so the probe measures a quiet, connected agent.
	time.Sleep(2 * time.Second)
	return h, ta, dev, plat, hwDelay
}

// TestRestartLatencyIdle is the ordinary case: an idle, connected agent. The restart must arrive by push within
// two seconds (it is typically a few milliseconds; the bound is generous for a loaded CI machine).
func TestRestartLatencyIdle(t *testing.T) {
	h, _, dev, plat, _ := latencyAgent(t)
	var api, sent, os []time.Duration
	for i := 0; i < 10; i++ {
		r := h.restartOnce(t, dev, plat.rebooted)
		api, sent, os = append(api, r.apiReturned), append(sent, r.serverSent), append(os, r.agentOS)
		if r.agentOS > 2*time.Second {
			t.Errorf("restart %d reached the operating system after %v; want under 2s", i, r.agentOS)
		}
	}
	t.Logf("click -> API returned   median %v max %v", median(api), maxDur(api))
	t.Logf("click -> server sent    median %v max %v", median(sent), maxDur(sent))
	t.Logf("click -> OS restart call median %v max %v", median(os), maxDur(os))
}

// TestRestartLatencyWhileAScanIsRunning: a Windows Update scan that is already running (the daily one, or a console
// "check now") must not hold a restart back.
func TestRestartLatencyWhileAScanIsRunning(t *testing.T) {
	h, _, dev, plat, _ := latencyAgent(t)
	plat.scanDelay.set(6 * time.Second)
	st, sc := h.do("POST", "/api/v1/devices/"+dev+"/windows-updates/scan", map[string]any{}, nil)
	if st != 202 {
		t.Fatalf("scan: %d %v", st, sc)
	}
	time.Sleep(500 * time.Millisecond) // the scan job is running now
	r := h.restartOnce(t, dev, plat.rebooted)
	t.Logf("restart during a 6s Windows Update scan reached the OS after %v", r.agentOS)
	if r.agentOS > 2*time.Second {
		t.Errorf("a running scan delayed the restart by %v; want under 2s", r.agentOS)
	}
	h.waitJobByID(sc["job_id"].(string), "succeeded")
}

// TestRestartLatencyWhileHardwareIsCollected: a slow hardware collection in the agent's stream loop (a refresh, the
// six-hourly report, or the first report after a start) must not hold a restart back.
func TestRestartLatencyWhileHardwareIsCollected(t *testing.T) {
	h, _, dev, plat, hwDelay := latencyAgent(t)
	hwDelay.set(6 * time.Second)
	// A refresh makes the agent collect hardware inside its stream loop.
	st, rf := h.do("POST", "/api/v1/devices/"+dev+"/refresh", map[string]any{}, nil)
	if st != 202 {
		t.Fatalf("refresh: %d %v", st, rf)
	}
	time.Sleep(1500 * time.Millisecond) // the refresh job is done; the slow collection is running
	r := h.restartOnce(t, dev, plat.rebooted)
	t.Logf("restart during a 6s hardware collection reached the OS after %v", r.agentOS)
	if r.agentOS > 2*time.Second {
		t.Errorf("a running hardware collection delayed the restart by %v; want under 2s", r.agentOS)
	}
}

// TestRestartLatencyRightAfterTheAgentConnects: after a PC starts, the agent reports hardware and software before it
// reads anything else. A restart sent in that window (the device is already shown online) must still arrive at once.
func TestRestartLatencyRightAfterTheAgentConnects(t *testing.T) {
	h, ta, dev, plat, hwDelay := latencyAgent(t)
	hwDelay.set(6 * time.Second)
	ta.stop()
	waitFor(t, 10*time.Second, "agent offline", func() bool { return h.device(dev)["online"] == false })
	ta2 := h.restartAgent(ta, func(a *core.Agent, st *store.Store) {
		a.Jobs = &jobs.Engine{P: plat, Store: st, Log: a.Log}
		a.HW = &slowHW{fakeHW: &fakeHW{host: "LAT-1", serial: "SLAT1", uuid: "ULAT1"}, delay: hwDelay}
	})
	_ = ta2
	waitFor(t, 10*time.Second, "agent online", func() bool { return h.device(dev)["online"] == true })
	r := h.restartOnce(t, dev, plat.rebooted)
	t.Logf("restart sent while the first inventory runs reached the OS after %v", r.agentOS)
	if r.agentOS > 2*time.Second {
		t.Errorf("the first inventory delayed the restart by %v; want under 2s", r.agentOS)
	}
}

func maxDur(d []time.Duration) time.Duration {
	m := d[0]
	for _, x := range d {
		m = max(m, x)
	}
	return m
}

// Clicks on Restart while an earlier restart for the device has not finished queue one restart, not several: they
// all get the first one's job back. Once that job has finished, a new click is a new restart. The agent is stopped
// (and the device left marked online, as it is for the seconds before the server notices a lost connection), so the
// first job cannot finish before the other clicks arrive; on a slow machine a finished job would be correct to replace.
func TestRestartClickedSeveralTimesIsOneJob(t *testing.T) {
	h, ta, dev, _, _ := latencyAgent(t)
	ta.stop()
	waitFor(t, 10*time.Second, "agent offline", func() bool { return h.device(dev)["online"] == false })
	if _, err := h.db.Pool.Exec(context.Background(), `UPDATE devices SET online = true WHERE id = $1`, dev); err != nil {
		t.Fatal(err)
	}
	click := func() string {
		st, rb := h.do("POST", "/api/v1/devices/"+dev+"/reboot", map[string]any{"minutes": 30, "reason": "several"}, nil)
		if st != 202 {
			t.Errorf("reboot: %d %v", st, rb)
			return ""
		}
		return rb["job_id"].(string)
	}
	const clicks = 8
	ids := make(chan string, clicks)
	for i := 0; i < clicks; i++ {
		go func() { ids <- click() }()
	}
	first := <-ids
	for i := 1; i < clicks; i++ {
		if id := <-ids; id != first {
			t.Fatalf("simultaneous clicks created more than one job: %s and %s", first, id)
		}
	}
	var jobsN int
	_ = h.db.Pool.QueryRow(context.Background(), `SELECT count(*) FROM jobs WHERE device_id = $1 AND type = 'reboot'`, dev).Scan(&jobsN)
	if jobsN != 1 {
		t.Fatalf("%d restart jobs stored; want 1", jobsN)
	}
	if n := h.auditCount("device.reboot"); n != clicks {
		t.Fatalf("%d audit entries for device.reboot; want %d (every click is recorded)", n, clicks)
	}
	// Once the job is finished, the next click is a new restart.
	if _, err := h.db.Pool.Exec(context.Background(), `UPDATE jobs SET status = 'succeeded', finished_at = now() WHERE id = $1`, first); err != nil {
		t.Fatal(err)
	}
	if next := click(); next == first || next == "" {
		t.Fatalf("a click after the job finished must be a new restart, got %q", next)
	}
}
