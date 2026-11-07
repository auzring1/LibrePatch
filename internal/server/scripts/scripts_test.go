package scripts

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"github.com/auzring1/librepatch/gen/dbq"
	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/deploy"
	"github.com/auzring1/librepatch/internal/server/pki"
	"github.com/auzring1/librepatch/internal/server/settings"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

type offers struct {
	mu  sync.Mutex
	got map[uuid.UUID][]*agentv1.SignedEnvelope
}

func (o *offers) Offer(id uuid.UUID, se *agentv1.SignedEnvelope) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.got[id] = append(o.got[id], se)
	return true
}

type fx struct {
	t      *testing.T
	pool   *pgxpool.Pool
	svc    *Service
	set    *settings.Service
	dep    *deploy.Service
	off    *offers
	org    uuid.UUID
	alice  uuid.UUID
	bob    uuid.UUID
	devs   []uuid.UUID
	groupA uuid.UUID
}

func newFx(t *testing.T) *fx {
	db := pgtest.New(t)
	h, err := pki.NewHierarchy("Contoso Health", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	auth := pki.NewAuthority(h.Root.Cert, h.Issuing, h.JobSigning)
	f := &fx{t: t, pool: db.Pool, org: uuid.New(), alice: uuid.New(), bob: uuid.New(), off: &offers{got: map[uuid.UUID][]*agentv1.SignedEnvelope{}}}
	f.dep = &deploy.Service{Pool: db.Pool, Authority: func() *pki.Authority { return auth }, Dispatcher: f.off}
	f.set = &settings.Service{Pool: db.Pool}
	f.svc = &Service{Pool: db.Pool, Deploy: f.dep, Settings: f.set}
	f.exec("INSERT INTO organizations (id, name) VALUES ($1, 'o')", f.org)
	site := uuid.New()
	f.exec("INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 's')", site, f.org)
	for _, u := range []uuid.UUID{f.alice, f.bob} {
		f.exec("INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, $3, $4, 'x')", u, f.org, u.String()+"@example.com", "user-"+u.String()[:4])
		f.exec("INSERT INTO role_bindings (id, user_id, role, scope_type, scope_id) VALUES ($1, $2, 'admin', 'org', $3)", uuid.New(), u, f.org)
	}
	for _, h := range []string{"pc-1", "pc-2", "pc-3"} {
		id := uuid.New()
		f.exec("INSERT INTO devices (id, org_id, site_id, status, hostname, arch) VALUES ($1,$2,$3,'active',$4,'amd64')", id, f.org, site, h)
		f.devs = append(f.devs, id)
	}
	f.groupA = uuid.New()
	f.exec("INSERT INTO groups (id, org_id, name, kind, created_by) VALUES ($1,$2,'g','static',$3)", f.groupA, f.org, f.alice)
	f.exec("INSERT INTO group_members (group_id, device_id) VALUES ($1,$2), ($1,$3)", f.groupA, f.devs[0], f.devs[1])
	return f
}

func (f *fx) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) count(sql string, args ...any) (n int) {
	f.t.Helper()
	if err := f.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return
}

func (f *fx) actor(u uuid.UUID) Actor { return Actor{Org: f.org, User: u, IP: "127.0.0.1"} }

func (f *fx) requireApproval(on bool) {
	f.t.Helper()
	doc, err := f.set.Get(context.Background(), f.org, "scripts")
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.set.Put(context.Background(), settings.Actor{Org: f.org, User: f.alice}, "scripts", doc.Revision, map[string]any{"require_approval": on}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) script(content string) uuid.UUID {
	f.t.Helper()
	id, err := f.svc.Create(context.Background(), f.actor(f.alice), Input{Name: "Clear cache " + uuid.NewString()[:4], Content: content})
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fx) jobBody(job uuid.UUID) *agentv1.RunScriptBody {
	var raw []byte
	if err := f.pool.QueryRow(context.Background(), "SELECT body FROM jobs WHERE id = $1", job).Scan(&raw); err != nil {
		f.t.Fatal(err)
	}
	var env agentv1.JobEnvelope
	if err := proto.Unmarshal(raw, &env); err != nil {
		f.t.Fatal(err)
	}
	return env.GetRunScript()
}

func TestLibraryKeepsEveryVersionAndAuditsEveryChange(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	a := f.actor(f.alice)
	id, err := f.svc.Create(ctx, a, Input{Name: "Clear cache", Description: "d", Content: "Remove-Item $env:TEMP\\x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Create(ctx, a, Input{Name: "Clear cache", Content: "x"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	// Same content: no new version. Different content: version 2.
	if v, err := f.svc.Update(ctx, a, id, Input{Name: "Clear cache", Description: "changed", Content: "Remove-Item $env:TEMP\\x"}); err != nil || v != 1 {
		t.Fatalf("%v %d", err, v)
	}
	if v, err := f.svc.Update(ctx, a, id, Input{Name: "Clear cache", Content: "Remove-Item $env:TEMP\\y", Note: "other file"}); err != nil || v != 2 {
		t.Fatalf("%v %d", err, v)
	}
	d, err := f.svc.Get(ctx, f.org, id, 0)
	if err != nil || d.Version != 2 || len(d.Versions) != 2 || d.Versions[0].Note != "other file" || !strings.HasSuffix(d.Content, "\\y") {
		t.Fatalf("%v %+v", err, d)
	}
	if old, _ := f.svc.Get(ctx, f.org, id, 1); old == nil || !strings.HasSuffix(old.Content, "\\x") {
		t.Fatalf("version 1 must stay readable: %+v", old)
	}
	for _, bad := range []Input{{Name: "", Content: "x"}, {Name: "n", Content: "  "}, {Name: "n", Content: strings.Repeat("a", MaxContent+1)}, {Name: "n", Content: "a\x00b"}, {Name: "n", Content: "a\xffb"}} {
		if _, err := f.svc.Create(ctx, a, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted", bad.Name)
		}
	}
	if err := f.svc.Delete(ctx, a, id); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Delete(ctx, a, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	for _, act := range []string{"script.create", "script.update", "script.delete"} {
		if f.count("SELECT count(*) FROM audit_log WHERE action = $1", act) == 0 {
			t.Errorf("no audit entry %s", act)
		}
	}
	var sha string
	_ = f.pool.QueryRow(ctx, "SELECT details->>'sha256' FROM audit_log WHERE action = 'script.update' AND details ? 'version'").Scan(&sha)
	if len(sha) != 64 {
		t.Fatalf("the audit entry carries the fingerprint of what was saved: %q", sha)
	}
}

func TestARunWithoutApprovalQueuesOneSignedJobPerDeviceWithTheExactContent(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	sid := f.script("Get-Process | Out-Null")
	run, err := f.svc.RequestRun(ctx, f.actor(f.alice), RunRequest{ScriptID: sid, GroupIDs: []uuid.UUID{f.groupA}, DeviceIDs: []uuid.UUID{f.devs[1], f.devs[2]}, Reason: "Disk cleanup ticket 4711"})
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "running" || run.Devices != 3 || run.NeedsApproval || run.TimeoutS != DefaultTimeoutS || run.SHA256 == "" {
		t.Fatalf("%+v", run)
	}
	d, err := f.svc.RunDetail(ctx, f.org, run.ID)
	if err != nil || len(d.Jobs) != 3 || d.Content != "Get-Process | Out-Null" {
		t.Fatalf("%v %+v", err, d)
	}
	b := f.jobBody(d.Jobs[0].JobID)
	if b.Content != d.Content || hex.EncodeToString(b.Sha256) != run.SHA256 || b.TimeoutS != DefaultTimeoutS || b.RunId != run.ID.String() || b.Interpreter != agentv1.ScriptInterpreter_SCRIPT_INTERPRETER_POWERSHELL {
		t.Fatalf("%+v", b)
	}
	f.dep.Wait()
	if f.count("SELECT count(*) FROM audit_log WHERE action IN ('script.run_request','script.run_start')") != 2 {
		t.Fatal("a run is audited when it is asked for and when it starts")
	}
	// Changing the script afterwards does not change what the run sent.
	if _, err := f.svc.Update(ctx, f.actor(f.alice), sid, Input{Name: "Clear cache x", Content: "Remove-Item C:\\ -Recurse"}); err != nil {
		t.Fatal(err)
	}
	if f.jobBody(d.Jobs[1].JobID).Content != "Get-Process | Out-Null" {
		t.Fatal("a queued job followed an edit of the script")
	}
}

func TestRunRequestsAreValidated(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	sid := f.script("x")
	ok := RunRequest{ScriptID: sid, DeviceIDs: f.devs[:1], Reason: "why"}
	for name, mut := range map[string]func(r *RunRequest){
		"no reason":   func(r *RunRequest) { r.Reason = "  " },
		"no targets":  func(r *RunRequest) { r.DeviceIDs = nil },
		"short limit": func(r *RunRequest) { r.TimeoutS = 3 },
		"long limit":  func(r *RunRequest) { r.TimeoutS = 99999 },
		"no version":  func(r *RunRequest) { r.Version = 9 },
		"nobody":      func(r *RunRequest) { r.DeviceIDs = []uuid.UUID{uuid.New()} },
	} {
		r := ok
		mut(&r)
		if _, err := f.svc.RequestRun(ctx, f.actor(f.alice), r); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	r := ok
	r.ScriptID = uuid.New()
	if _, err := f.svc.RequestRun(ctx, f.actor(f.alice), r); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown script: %v", err)
	}
	// Another organization's script is invisible.
	if _, err := f.svc.RequestRun(ctx, Actor{Org: uuid.New(), User: f.alice}, ok); !errors.Is(err, ErrNotFound) {
		t.Errorf("another organization: %v", err)
	}
}

func TestARunThatNeedsApprovalSendsNothingUntilAnotherAdministratorApproves(t *testing.T) {
	f := newFx(t)
	f.requireApproval(true)
	ctx := context.Background()
	sid := f.script("Restart-Service Spooler")
	run, err := f.svc.RequestRun(ctx, f.actor(f.alice), RunRequest{ScriptID: sid, DeviceIDs: f.devs[:2], Reason: "printer queue stuck"})
	if err != nil || run.Status != "pending_approval" || !run.NeedsApproval {
		t.Fatalf("%v %+v", err, run)
	}
	if f.count("SELECT count(*) FROM jobs WHERE script_run_id = $1", run.ID) != 0 {
		t.Fatal("jobs exist before approval")
	}
	// The person who asked cannot approve.
	if _, err := f.svc.Approve(ctx, f.actor(f.alice), run.ID, ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("self approval: %v", err)
	}
	// The script is edited while the request waits: the approver approves the copy that was requested.
	if _, err := f.svc.Update(ctx, f.actor(f.alice), sid, Input{Name: "renamed", Content: "Stop-Computer -Force"}); err != nil {
		t.Fatal(err)
	}
	got, err := f.svc.Approve(ctx, f.actor(f.bob), run.ID, "ok, looked at it")
	if err != nil || got.Status != "running" || got.DecidedBy == "" {
		t.Fatalf("%v %+v", err, got)
	}
	d, _ := f.svc.RunDetail(ctx, f.org, run.ID)
	if len(d.Jobs) != 2 || f.jobBody(d.Jobs[0].JobID).Content != "Restart-Service Spooler" {
		t.Fatalf("the approved copy must be what is sent: %+v", d.Jobs)
	}
	f.dep.Wait()
	// A decided run cannot be decided again.
	if _, err := f.svc.Approve(ctx, f.actor(f.bob), run.ID, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("second approval: %v", err)
	}
	if _, err := f.svc.Reject(ctx, f.actor(f.bob), run.ID, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("reject after approval: %v", err)
	}
	for _, act := range []string{"script.run_request", "script.run_approve", "script.run_start"} {
		if f.count("SELECT count(*) FROM audit_log WHERE action = $1", act) == 0 {
			t.Errorf("no audit entry %s", act)
		}
	}
}

func TestRejectCancelAndExpiry(t *testing.T) {
	f := newFx(t)
	f.requireApproval(true)
	ctx := context.Background()
	sid := f.script("x")
	req := func() *RunView {
		r, err := f.svc.RequestRun(ctx, f.actor(f.alice), RunRequest{ScriptID: sid, DeviceIDs: f.devs[:1], Reason: "why"})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r1 := req()
	if got, err := f.svc.Reject(ctx, f.actor(f.bob), r1.ID, "not now"); err != nil || got.Status != "rejected" || got.Note != "not now" {
		t.Fatalf("%v %+v", err, got)
	}
	if f.count("SELECT count(*) FROM jobs WHERE script_run_id = $1", r1.ID) != 0 {
		t.Fatal("a rejected run created jobs")
	}
	r2 := req()
	if got, err := f.svc.Cancel(ctx, f.actor(f.alice), r2.ID); err != nil || got.Status != "cancelled" {
		t.Fatalf("%v %+v", err, got)
	}
	if _, err := f.svc.Cancel(ctx, f.actor(f.alice), r2.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("cancel twice: %v", err)
	}
	r3 := req()
	f.exec("UPDATE script_runs SET requested_at = now() - interval '25 hours' WHERE id = $1", r3.ID)
	if _, err := f.svc.Approve(ctx, f.actor(f.bob), r3.ID, ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("an old request: %v", err)
	}
	if v, _ := f.svc.GetRun(ctx, f.org, r3.ID); v.Status != "expired" {
		t.Fatalf("%+v", v)
	}
	// Cancelling a running run cancels its jobs that have not started.
	f.requireApproval(false)
	r4, _ := f.svc.RequestRun(ctx, f.actor(f.alice), RunRequest{ScriptID: sid, DeviceIDs: f.devs[:2], Reason: "why"})
	f.dep.Wait()
	if got, err := f.svc.Cancel(ctx, f.actor(f.alice), r4.ID); err != nil || got.Status != "cancelled" {
		t.Fatalf("%v %+v", err, got)
	}
	if n := f.count("SELECT count(*) FROM jobs WHERE script_run_id = $1 AND status = 'cancelled'", r4.ID); n != 2 {
		t.Fatalf("cancelled jobs: %d", n)
	}
}

func TestScriptOutputIsKeptApartFromTheJobResult(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	sid := f.script("Write-Output $env:SECRET")
	run, err := f.svc.RequestRun(ctx, f.actor(f.alice), RunRequest{ScriptID: sid, DeviceIDs: f.devs[:1], Reason: "why"})
	if err != nil {
		t.Fatal(err)
	}
	f.dep.Wait()
	d, _ := f.svc.RunDetail(ctx, f.org, run.ID)
	job := d.Jobs[0].JobID
	dev, _ := dbq.New(f.pool).GetDevice(ctx, f.devs[0])
	for _, st := range []agentv1.JobState{agentv1.JobState_JOB_STATE_ACCEPTED, agentv1.JobState_JOB_STATE_RUNNING} {
		if err := f.dep.ApplyUpdate(ctx, dev, &agentv1.JobUpdate{JobId: job.String(), Attempt: 1, State: st}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.dep.ApplyUpdate(ctx, dev, &agentv1.JobUpdate{JobId: job.String(), Attempt: 1, State: agentv1.JobState_JOB_STATE_FAILED, Reason: "script_failed",
		Result: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_FAILED, ExitCode: 7, Message: "script exit code 7", LogTail: "password=hunter2"}}); err != nil {
		t.Fatal(err)
	}
	var result string
	_ = f.pool.QueryRow(ctx, "SELECT result::text FROM jobs WHERE id = $1", job).Scan(&result)
	if strings.Contains(result, "hunter2") || !strings.Contains(result, "script exit code 7") {
		t.Fatalf("the job result that job pages show must not carry the output: %s", result)
	}
	o, err := f.svc.GetOutput(ctx, f.org, run.ID, job)
	if err != nil || o.Output != "password=hunter2" || o.ExitCode != 7 {
		t.Fatalf("%v %+v", err, o)
	}
	if _, err := f.svc.GetOutput(ctx, f.org, uuid.New(), job); !errors.Is(err, ErrNotFound) {
		t.Fatalf("output under another run: %v", err)
	}
	if _, err := f.svc.GetOutput(ctx, uuid.New(), run.ID, job); !errors.Is(err, ErrNotFound) {
		t.Fatalf("output in another organization: %v", err)
	}
	d, _ = f.svc.RunDetail(ctx, f.org, run.ID)
	if !d.Jobs[0].HasOutput || d.Failed != 1 {
		t.Fatalf("%+v", d)
	}
}

func TestARunShowsWhatItCameToOnceEveryJobIsDone(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	run, err := f.svc.RequestRun(ctx, f.actor(f.alice), RunRequest{ScriptID: f.script("1"), DeviceIDs: f.devs[:2], Reason: "why"})
	if err != nil {
		t.Fatal(err)
	}
	f.dep.Wait()
	state := func() (string, string) {
		d, err := f.svc.RunDetail(ctx, f.org, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		rows, _ := f.svc.ListRuns(ctx, f.org, 10)
		return d.Status, rows[0].Status
	}
	if a, b := state(); a != "running" || b != "running" {
		t.Fatalf("jobs are still open: %s %s", a, b)
	}
	d, _ := f.svc.RunDetail(ctx, f.org, run.ID)
	finish := func(job uuid.UUID, dev uuid.UUID, st agentv1.JobState, out agentv1.JobOutcome) {
		row, _ := dbq.New(f.pool).GetDevice(ctx, dev)
		for _, s := range []agentv1.JobState{agentv1.JobState_JOB_STATE_ACCEPTED, agentv1.JobState_JOB_STATE_RUNNING} {
			if err := f.dep.ApplyUpdate(ctx, row, &agentv1.JobUpdate{JobId: job.String(), Attempt: 1, State: s}); err != nil {
				t.Fatal(err)
			}
		}
		if err := f.dep.ApplyUpdate(ctx, row, &agentv1.JobUpdate{JobId: job.String(), Attempt: 1, State: st, Result: &agentv1.JobResult{Outcome: out}}); err != nil {
			t.Fatal(err)
		}
	}
	finish(d.Jobs[0].JobID, d.Jobs[0].DeviceID, agentv1.JobState_JOB_STATE_SUCCEEDED, agentv1.JobOutcome_JOB_OUTCOME_SUCCESS)
	if a, b := state(); a != "running" || b != "running" {
		t.Fatalf("one job is still open: %s %s", a, b)
	}
	finish(d.Jobs[1].JobID, d.Jobs[1].DeviceID, agentv1.JobState_JOB_STATE_FAILED, agentv1.JobOutcome_JOB_OUTCOME_FAILED)
	if a, b := state(); a != "completed_with_errors" || b != "completed_with_errors" {
		t.Fatalf("one worked and one failed: %s %s", a, b)
	}
}

func TestSettledStates(t *testing.T) {
	for _, c := range []struct {
		status        string
		open, ok, bad int64
		want          string
	}{
		{"running", 1, 5, 0, "running"},
		{"running", 0, 5, 0, "completed"},
		{"running", 0, 3, 2, "completed_with_errors"},
		{"running", 0, 0, 2, "failed"},
		{"running", 0, 0, 0, "cancelled"},
		{"pending_approval", 0, 0, 0, "pending_approval"},
		{"rejected", 0, 0, 0, "rejected"},
	} {
		if got := settled(c.status, c.open, c.ok, c.bad); got != c.want {
			t.Errorf("%+v: got %s", c, got)
		}
	}
}

func TestApproverCount(t *testing.T) {
	f := newFx(t)
	if n := f.svc.OtherApprovers(context.Background(), f.org, f.alice); n != 1 {
		t.Fatalf("%d", n)
	}
	f.exec("UPDATE users SET status = 'disabled' WHERE id = $1", f.bob)
	if n := f.svc.OtherApprovers(context.Background(), f.org, f.alice); n != 0 {
		t.Fatalf("a disabled administrator cannot approve: %d", n)
	}
}

// Scripts are on until an administrator switches them off in Settings (D150); off, nothing can be run or approved.
func TestScriptsAreOnByDefaultAndTheSettingSwitchesThemOff(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	if !f.svc.Enabled(ctx, f.org) {
		t.Fatal("scripts should be on by default")
	}
	sid := f.script("Get-Date")
	req := RunRequest{ScriptID: sid, DeviceIDs: f.devs[:1], Reason: "check the clock"}
	if _, err := f.svc.RequestRun(ctx, f.actor(f.alice), req); err != nil {
		t.Fatalf("a run with the default settings: %v", err)
	}

	// A run that waits for approval cannot be approved while scripts are off.
	f.requireApproval(true)
	waiting, err := f.svc.RequestRun(ctx, f.actor(f.alice), req)
	if err != nil || waiting.Status != "pending_approval" {
		t.Fatalf("%v %+v", err, waiting)
	}
	f.setScripts(map[string]any{"require_approval": true, "enabled": false})
	if f.svc.Enabled(ctx, f.org) {
		t.Fatal("the setting did not switch scripts off")
	}
	if _, err := f.svc.RequestRun(ctx, f.actor(f.alice), req); !errors.Is(err, ErrDisabled) {
		t.Fatalf("a run while scripts are off: %v", err)
	}
	if _, err := f.svc.Approve(ctx, f.actor(f.bob), waiting.ID, ""); !errors.Is(err, ErrDisabled) {
		t.Fatalf("an approval while scripts are off: %v", err)
	}
	if n := f.count("SELECT count(*) FROM jobs WHERE script_run_id = $1", waiting.ID); n != 0 {
		t.Fatalf("%d jobs were created while scripts are off", n)
	}

	// Switched on again, the same request can be approved.
	f.setScripts(map[string]any{"require_approval": true, "enabled": true})
	if _, err := f.svc.Approve(ctx, f.actor(f.bob), waiting.ID, ""); err != nil {
		t.Fatalf("approval after switching on: %v", err)
	}
}

func (f *fx) setScripts(values map[string]any) {
	f.t.Helper()
	doc, err := f.set.Get(context.Background(), f.org, "scripts")
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.set.Put(context.Background(), settings.Actor{Org: f.org, User: f.alice}, "scripts", doc.Revision, values); err != nil {
		f.t.Fatal(err)
	}
}
