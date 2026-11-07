package jobs

import (
	"errors"
	"testing"
	"time"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/agent/wu"
)

const (
	idKB1 = "11111111-1111-1111-1111-111111111111"
	idKB2 = "22222222-2222-2222-2222-222222222222"
	idKB3 = "33333333-3333-3333-3333-333333333333"
)

func (r *rig) wuEnv(id string, typ agentv1.JobType, mut func(*agentv1.JobEnvelope)) (*agentv1.SignedEnvelope, *agentv1.JobEnvelope) {
	env := &agentv1.JobEnvelope{Version: 1, JobId: id, OrgId: "o", DeviceId: "d", Type: typ,
		IssuedAt: r.now.Unix(), NotBefore: r.now.Unix(), ExpiresAt: r.now.Add(24 * time.Hour).Unix(), Nonce: make([]byte, 16)}
	refs := []*agentv1.WuUpdateRef{{UpdateId: idKB1}, {UpdateId: idKB2}}
	switch typ {
	case agentv1.JobType_JOB_TYPE_WU_SCAN:
		env.Body = &agentv1.JobEnvelope_WuScan{WuScan: &agentv1.WuScanBody{Service: agentv1.WuService_WU_SERVICE_MICROSOFT_UPDATE, IncludeDrivers: true}}
	case agentv1.JobType_JOB_TYPE_WU_INSTALL:
		env.Body = &agentv1.JobEnvelope_WuInstall{WuInstall: &agentv1.WuInstallBody{Updates: refs,
			Reboot: &agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_NEVER}, MaxRetries: 1, RetryBackoffS: 30}}
	case agentv1.JobType_JOB_TYPE_WU_HIDE:
		env.Body = &agentv1.JobEnvelope_WuHide{WuHide: &agentv1.WuHideBody{Updates: refs[:1], Hide: true}}
	case agentv1.JobType_JOB_TYPE_REBOOT:
		env.Body = &agentv1.JobEnvelope_Reboot{Reboot: &agentv1.RebootBody{Reason: "maintenance",
			Reboot: &agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_NOW, NotifyMinutes: 5}}}
	}
	if mut != nil {
		mut(env)
	}
	return r.sign(env), env
}

func (r *rig) offerUpdates(ids ...string) {
	for _, id := range ids {
		r.p.wuc.updates = append(r.p.wuc.updates, &agentv1.WuUpdate{UpdateId: id, Revision: 1, Title: "Update " + id[:2],
			Classification: "Security Updates", State: agentv1.WuUpdateState_WU_UPDATE_STATE_MISSING})
	}
}

func (r *rig) run(id string, se *agentv1.SignedEnvelope, env *agentv1.JobEnvelope) *agentv1.JobResult {
	r.e.Accept(se, env)
	r.tick()
	if last := r.rec.last(id); last != nil {
		return last.Result
	}
	return nil
}

func TestWUScanReportsSnapshotAndRemembersOptions(t *testing.T) {
	r := newRig(t)
	r.offerUpdates(idKB1, idKB2)
	var got *agentv1.WuInventory
	r.e.WUReport = func(s *agentv1.WuInventory) { got = s }
	se, env := r.wuEnv("s1", agentv1.JobType_JOB_TYPE_WU_SCAN, nil)
	res := r.run("s1", se, env)
	if r.state("s1") != agentv1.JobState_JOB_STATE_SUCCEEDED || res.Message != "2 update(s) available, 0 hidden" {
		t.Fatalf("%v %+v", r.state("s1"), res)
	}
	if got == nil || len(got.Updates) != 2 || got.Service != int32(agentv1.WuService_WU_SERVICE_MICROSOFT_UPDATE) || got.Policy == nil {
		t.Fatalf("snapshot: %+v", got)
	}
	if o := r.p.wuc.opts[0]; o.Service != agentv1.WuService_WU_SERVICE_MICROSOFT_UPDATE || !o.IncludeDrivers {
		t.Fatalf("scan options: %+v", o)
	}
	if o := r.e.storedWUOptions(); o.Service != agentv1.WuService_WU_SERVICE_MICROSOFT_UPDATE || !o.IncludeDrivers {
		t.Fatalf("options were not remembered for the automatic scan: %+v", o)
	}
}

func TestWUOneOffScanDoesNotChangeTheOptionsOfTheDailyScan(t *testing.T) {
	r := newRig(t)
	r.offerUpdates(idKB1)
	// the normal scan remembers the organization's source (here: the machine's own, e.g. WSUS)
	se, env := r.wuEnv("n1", agentv1.JobType_JOB_TYPE_WU_SCAN, func(e *agentv1.JobEnvelope) {
		e.GetWuScan().Service, e.GetWuScan().IncludeDrivers = agentv1.WuService_WU_SERVICE_DEFAULT, false
	})
	r.run("n1", se, env)
	// an administrator's one-off check against the internet
	var got *agentv1.WuInventory
	r.e.WUReport = func(s *agentv1.WuInventory) { got = s }
	se, env = r.wuEnv("o1", agentv1.JobType_JOB_TYPE_WU_SCAN, func(e *agentv1.JobEnvelope) {
		b := e.GetWuScan()
		b.Service, b.IncludeDrivers, b.OneOff = agentv1.WuService_WU_SERVICE_WINDOWS_UPDATE, false, true
	})
	r.run("o1", se, env)
	if r.state("o1") != agentv1.JobState_JOB_STATE_SUCCEEDED || got == nil || got.Service != int32(agentv1.WuService_WU_SERVICE_WINDOWS_UPDATE) {
		t.Fatalf("one-off scan: %v %+v", r.state("o1"), got)
	}
	if o := r.p.wuc.opts[len(r.p.wuc.opts)-1]; o.Service != agentv1.WuService_WU_SERVICE_WINDOWS_UPDATE {
		t.Fatalf("the one-off scan did not use the requested source: %+v", o)
	}
	if o := r.e.storedWUOptions(); o.Service != agentv1.WuService_WU_SERVICE_DEFAULT {
		t.Fatalf("a one-off scan changed the options of the automatic scan: %+v", o)
	}
}

func TestWUOneOffInstallDoesNotChangeTheOptionsOfTheDailyScan(t *testing.T) {
	r := newRig(t)
	r.offerUpdates(idKB1, idKB2)
	se, env := r.wuEnv("n2", agentv1.JobType_JOB_TYPE_WU_SCAN, func(e *agentv1.JobEnvelope) {
		e.GetWuScan().Service, e.GetWuScan().IncludeDrivers = agentv1.WuService_WU_SERVICE_DEFAULT, false
	})
	r.run("n2", se, env)
	se, env = r.wuEnv("o2", agentv1.JobType_JOB_TYPE_WU_INSTALL, func(e *agentv1.JobEnvelope) {
		b := e.GetWuInstall()
		b.Service, b.OneOff = agentv1.WuService_WU_SERVICE_WINDOWS_UPDATE, true
	})
	r.run("o2", se, env)
	if r.state("o2") != agentv1.JobState_JOB_STATE_SUCCEEDED {
		t.Fatalf("one-off install: %v", r.state("o2"))
	}
	for _, o := range r.p.wuc.opts[1:] {
		if o.Service != agentv1.WuService_WU_SERVICE_WINDOWS_UPDATE {
			t.Fatalf("the one-off install or its rescan used another source: %+v", r.p.wuc.opts)
		}
	}
	if o := r.e.storedWUOptions(); o.Service != agentv1.WuService_WU_SERVICE_DEFAULT {
		t.Fatalf("a one-off install changed the options of the automatic scan: %+v", o)
	}
}

func TestWUScanFailureIsReportedInTheSnapshot(t *testing.T) {
	r := newRig(t)
	r.p.wuc.err = errors.New("0x80072ee2: the server name or address could not be resolved")
	var got *agentv1.WuInventory
	r.e.WUReport = func(s *agentv1.WuInventory) { got = s }
	se, env := r.wuEnv("s2", agentv1.JobType_JOB_TYPE_WU_SCAN, nil)
	res := r.run("s2", se, env)
	if r.state("s2") != agentv1.JobState_JOB_STATE_FAILED || got == nil || got.ScanError == "" || len(got.Updates) != 0 || res.Message == "" {
		t.Fatalf("%v %+v %+v", r.state("s2"), got, res)
	}
}

func TestWUInstallReportsEveryUpdateAndRescans(t *testing.T) {
	r := newRig(t)
	r.offerUpdates(idKB1, idKB2, idKB3)
	r.p.wuc.results[idKB2] = agentv1.WuResult_WU_RESULT_FAILED
	var snaps []*agentv1.WuInventory
	r.e.WUReport = func(s *agentv1.WuInventory) { snaps = append(snaps, s) }
	se, env := r.wuEnv("i1", agentv1.JobType_JOB_TYPE_WU_INSTALL, nil)
	res := r.run("i1", se, env)
	// one installed, one failed: the job fails, but both results are reported
	if r.state("i1") != agentv1.JobState_JOB_STATE_FAILED || len(res.WuResults) != 2 || res.Message != "1 installed, 1 failed, 0 no longer applicable" {
		t.Fatalf("%v %+v", r.state("i1"), res)
	}
	if res.WuResults[0].Result != agentv1.WuResult_WU_RESULT_INSTALLED || res.WuResults[1].Result != agentv1.WuResult_WU_RESULT_FAILED {
		t.Fatalf("results: %+v", res.WuResults)
	}
	// only the named updates were installed; the one not named stays missing; a fresh snapshot followed
	if len(r.p.wuc.installs) != 1 || len(r.p.wuc.installs[0]) != 2 {
		t.Fatalf("installs: %+v", r.p.wuc.installs)
	}
	if len(snaps) != 1 || len(snaps[0].Updates) != 2 {
		t.Fatalf("rescan snapshot: %+v", snaps)
	}
}

func TestWUInstallRebootPolicies(t *testing.T) {
	loc := time.UTC
	_ = loc
	cases := []struct {
		name     string
		policy   *agentv1.RebootPolicy
		wantPlan bool
		dueAfter time.Duration // relative to the rig clock (12:00 UTC)
	}{
		{"never", &agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_NEVER}, false, 0},
		{"outside active hours (inside them now)", &agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_OUTSIDE_ACTIVE_HOURS, NotifyMinutes: 10,
			ActiveHours: &agentv1.ActiveHours{StartMinute: 8 * 60, EndMinute: 17 * 60}}, true, 5 * time.Hour},
		{"outside active hours (already outside)", &agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_OUTSIDE_ACTIVE_HOURS, NotifyMinutes: 10,
			ActiveHours: &agentv1.ActiveHours{StartMinute: 20 * 60, EndMinute: 23 * 60}}, true, 0},
		{"deadline in two hours, 15 minute notice", &agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_DEADLINE, NotifyMinutes: 15,
			DeadlineAt: time.Date(2026, 10, 7, 14, 0, 0, 0, time.UTC).Unix()}, true, 105 * time.Minute},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.offerUpdates(idKB1)
			r.p.wuc.reboot = true
			se, env := r.wuEnv("i", agentv1.JobType_JOB_TYPE_WU_INSTALL, func(e *agentv1.JobEnvelope) {
				e.GetWuInstall().Updates = e.GetWuInstall().Updates[:1]
				e.GetWuInstall().Reboot = c.policy
			})
			r.p.rebootReq = true
			res := r.run("i", se, env)
			if r.state("i") != agentv1.JobState_JOB_STATE_SUCCEEDED_REBOOT || !res.RebootRequired {
				t.Fatalf("an install that needs a restart succeeds with reboot required: %v %+v", r.state("i"), res)
			}
			plan := r.e.loadRebootPlan()
			if (plan != nil) != c.wantPlan {
				t.Fatalf("plan = %+v", plan)
			}
			if plan != nil && time.Unix(plan.Due, 0).Sub(r.now) != c.dueAfter {
				t.Fatalf("due in %s, want %s", time.Unix(plan.Due, 0).Sub(r.now), c.dueAfter)
			}
		})
	}
}

func TestRebootStartsCountdownWhenDueAndNeverInsideActiveHours(t *testing.T) {
	r := newRig(t)
	r.p.rebootReq = true
	r.e.init()
	// Plan due now with active hours covering the current time (e.g. the clock moved): it waits.
	r.e.saveRebootPlan(&rebootPlan{Due: r.now.Unix(), NotifyMin: 10, Reason: "updates", Active: []uint32{8 * 60, 17 * 60}})
	if next := r.e.checkReboot(); !next.Equal(time.Date(2026, 10, 7, 17, 0, 0, 0, time.UTC)) || len(r.p.reboots) != 0 {
		t.Fatalf("restart inside active hours: next=%v reboots=%v", next, r.p.reboots)
	}
	r.now = time.Date(2026, 10, 7, 17, 1, 0, 0, time.UTC)
	r.e.checkReboot()
	if len(r.p.reboots) != 1 || r.p.reboots[0].delay != 10*time.Minute {
		t.Fatalf("reboots: %+v", r.p.reboots)
	}
	// fired once; not repeated while the plan lives
	r.e.checkReboot()
	if len(r.p.reboots) != 1 {
		t.Fatalf("restart repeated: %+v", r.p.reboots)
	}
	// once nothing is pending any more the plan is dropped
	r.p.rebootReq = false
	r.e.checkReboot()
	if r.e.loadRebootPlan() != nil {
		t.Fatal("a finished plan was kept")
	}
}

func TestRebootPlanCancelledWhenUserRestartsFirst(t *testing.T) {
	r := newRig(t)
	r.p.rebootReq = true
	r.e.init()
	r.e.scheduleReboot(&agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_OUTSIDE_ACTIVE_HOURS, NotifyMinutes: 5,
		ActiveHours: &agentv1.ActiveHours{StartMinute: 8 * 60, EndMinute: 17 * 60}}, "updates", false)
	r.p.rebootReq = false // the user restarted before the plan came due
	r.now = time.Date(2026, 10, 7, 18, 0, 0, 0, time.UTC)
	r.e.checkReboot()
	if len(r.p.reboots) != 0 || r.e.loadRebootPlan() != nil {
		t.Fatalf("restarted a machine that no longer needed it: %+v", r.p.reboots)
	}
}

func TestRebootJobIsImmediateWithCountdown(t *testing.T) {
	r := newRig(t)
	se, env := r.wuEnv("rb", agentv1.JobType_JOB_TYPE_REBOOT, nil)
	r.e.Accept(se, env)
	r.tick()
	if r.state("rb") != agentv1.JobState_JOB_STATE_SUCCEEDED || len(r.p.reboots) != 1 || r.p.reboots[0].delay != 5*time.Minute {
		t.Fatalf("%v %+v", r.state("rb"), r.p.reboots)
	}
	if m := r.p.reboots[0].message; m == "" {
		t.Fatal("signed-in users must be told why")
	}
}

func TestWUHideAndFailures(t *testing.T) {
	r := newRig(t)
	r.offerUpdates(idKB1)
	se, env := r.wuEnv("h1", agentv1.JobType_JOB_TYPE_WU_HIDE, nil)
	if res := r.run("h1", se, env); r.state("h1") != agentv1.JobState_JOB_STATE_SUCCEEDED || res.Message != "1 update(s) hidden" || !r.p.wuc.hidden[idKB1] {
		t.Fatalf("%v %+v", r.state("h1"), res)
	}
	// Windows Update unavailable: an install is retried with back-off instead of failing at once.
	r2 := newRig(t)
	r2.p.wuc.err = wu.ErrUnavailable
	se, env = r2.wuEnv("i2", agentv1.JobType_JOB_TYPE_WU_INSTALL, nil)
	r2.run("i2", se, env)
	if r2.state("i2") != agentv1.JobState_JOB_STATE_WAITING || r2.rec.last("i2").Reason != "retry_backoff" {
		t.Fatalf("%v %+v", r2.state("i2"), r2.rec.last("i2"))
	}
}

func TestWUJobValidationAndCeiling(t *testing.T) {
	bad := []struct {
		name string
		mut  func(*agentv1.JobEnvelope)
	}{
		{"user scope", func(e *agentv1.JobEnvelope) { e.TargetUserSid = "S-1-5-21-1-2-3-1001" }},
		{"no updates", func(e *agentv1.JobEnvelope) { e.GetWuInstall().Updates = nil }},
		{"malformed id", func(e *agentv1.JobEnvelope) { e.GetWuInstall().Updates[0].UpdateId = "KB5000001" }},
		{"negative revision", func(e *agentv1.JobEnvelope) { e.GetWuInstall().Updates[0].Revision = -1 }},
		{"install demanding an immediate reboot", func(e *agentv1.JobEnvelope) {
			e.GetWuInstall().Reboot = &agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_NOW, NotifyMinutes: 1}
		}},
		{"deadline without a deadline", func(e *agentv1.JobEnvelope) {
			e.GetWuInstall().Reboot = &agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_DEADLINE}
		}},
		{"active hours out of range", func(e *agentv1.JobEnvelope) {
			e.GetWuInstall().Reboot = &agentv1.RebootPolicy{Allow: agentv1.RebootAllow_REBOOT_ALLOW_OUTSIDE_ACTIVE_HOURS, ActiveHours: &agentv1.ActiveHours{StartMinute: 2000}}
		}},
	}
	for _, c := range bad {
		r := newRig(t)
		se, env := r.wuEnv("v", agentv1.JobType_JOB_TYPE_WU_INSTALL, c.mut)
		r.e.Accept(se, env)
		if r.state("v") != agentv1.JobState_JOB_STATE_REJECTED {
			t.Errorf("%s was accepted: %v", c.name, r.state("v"))
		}
	}
	r := newRig(t)
	se, env := r.wuEnv("rb2", agentv1.JobType_JOB_TYPE_REBOOT, func(e *agentv1.JobEnvelope) { e.GetReboot().Reboot.NotifyMinutes = 0 })
	r.e.Accept(se, env)
	if r.state("rb2") != agentv1.JobState_JOB_STATE_REJECTED {
		t.Errorf("an immediate restart without a countdown was accepted")
	}
	// The local policy ceiling applies to the new types.
	r = newRig(t)
	r.e.Allowed = map[string]bool{"inventory": true, "wu_scan": true}
	se, env = r.wuEnv("c1", agentv1.JobType_JOB_TYPE_WU_INSTALL, nil)
	r.e.Accept(se, env)
	if r.state("c1") != agentv1.JobState_JOB_STATE_REJECTED || len(r.rec.sec) != 1 {
		t.Fatalf("ceiling: %v %v", r.state("c1"), r.rec.sec)
	}
	se, env = r.wuEnv("c2", agentv1.JobType_JOB_TYPE_REBOOT, nil)
	r.e.Accept(se, env)
	if r.state("c2") != agentv1.JobState_JOB_STATE_REJECTED {
		t.Fatalf("reboot is outside the ceiling: %v", r.state("c2"))
	}
}

func TestAutomaticScanRunsDailyWithStoredOptions(t *testing.T) {
	r := newRig(t)
	r.offerUpdates(idKB1)
	r.e.WUScanEvery = 24 * time.Hour
	scans := 0
	r.e.WUReport = func(*agentv1.WuInventory) { scans++ }
	r.e.saveWUOptions(wu.Options{Service: agentv1.WuService_WU_SERVICE_WINDOWS_UPDATE})
	r.tick() // the first tick only schedules the first scan, a few minutes ahead
	if scans != 0 {
		t.Fatal("scanned immediately at start")
	}
	r.now = r.now.Add(11 * time.Minute)
	r.tick()
	if scans != 1 || r.p.wuc.opts[0].Service != agentv1.WuService_WU_SERVICE_WINDOWS_UPDATE {
		t.Fatalf("scans=%d opts=%+v", scans, r.p.wuc.opts)
	}
	r.now = r.now.Add(time.Hour)
	r.tick()
	if scans != 1 {
		t.Fatal("scanned again within the day")
	}
	r.now = r.now.Add(27 * time.Hour)
	r.tick()
	if scans != 2 {
		t.Fatalf("no scan after a day: %d", scans)
	}
	// A ceiling without wu_scan switches the automatic scan off.
	r2 := newRig(t)
	r2.e.WUScanEvery = time.Hour
	r2.e.Allowed = map[string]bool{"inventory": true}
	n := 0
	r2.e.WUReport = func(*agentv1.WuInventory) { n++ }
	r2.tick()
	r2.now = r2.now.Add(24 * time.Hour)
	r2.tick()
	if n != 0 {
		t.Fatal("scanned although wu_scan is not allowed locally")
	}
}
