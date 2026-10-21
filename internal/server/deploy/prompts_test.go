package deploy

import (
	"errors"
	"testing"

	"github.com/google/uuid"

	agentv1 "github.com/auzring1/librepatch/gen/proto/librepatch/agent/v1"
	"github.com/auzring1/librepatch/internal/server/catalog"
)

func TestPromptsValidate(t *testing.T) {
	for _, p := range []*Prompts{nil, {}, {InUse: "ignore", Restart: "none"}} {
		if v, err := p.Validate(); err != nil || v != nil {
			t.Fatalf("%+v must be silent: %+v %v", p, v, err)
		}
	}
	good := &Prompts{InUse: "ask", AskTimeoutS: 120, DeferMinutes: 30, Restart: "countdown", RestartNotifyMinutes: 10}
	if v, err := good.Validate(); err != nil || v == nil {
		t.Fatalf("%v", err)
	}
	for _, bad := range []*Prompts{{InUse: "kill"}, {Restart: "now"}, {InUse: "ask", AskTimeoutS: 5}, {InUse: "ask", DeferMinutes: 2},
		{Restart: "ask", RestartNotifyMinutes: 99999}, {InUse: "ask", AskTimeoutS: 99999}} {
		if _, err := bad.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v accepted: %v", bad, err)
		}
	}
	if got := MarshalPrompts(&Prompts{InUse: "ignore"}); got != nil {
		t.Fatalf("silent prompts are stored as null: %s", got)
	}
	if rt := ParsePrompts(MarshalPrompts(good)); rt == nil || *rt != *good {
		t.Fatalf("round trip: %+v", rt)
	}
}

func TestPromptsReachTheSignedJob(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	dev := f.device("pc", "amd64")
	f.rec.setOnline(dev)
	body := func(plan *Plan) *agentv1.InstallBody {
		jobs := f.jobs(plan.DeploymentID)
		if len(jobs) != 1 {
			t.Fatalf("jobs: %d", len(jobs))
		}
		return envOf(t, jobs[0]).GetInstall()
	}

	// Silent by default: nothing about prompts in the job.
	plan, err := f.create(Request{Action: "install", Version: "2.0", Scope: "machine", DeviceIDs: []uuid.UUID{dev}})
	if err != nil {
		t.Fatal(err)
	}
	if body(plan).Prompts != nil {
		t.Fatalf("a deployment without prompts must stay silent: %+v", body(plan).Prompts)
	}

	// Waiting for, asking about or closing programs needs the package's program names.
	_, err = f.create(Request{Name: "ask", Action: "install", Version: "2.0", Scope: "machine", DeviceIDs: []uuid.UUID{dev}, Prompts: &Prompts{InUse: "ask"}})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("no program names: %v", err)
	}
	f.exec("INSERT INTO package_overrides (org_id, package_id, processes) VALUES ($1,$2,$3)", f.org, f.pkg.ID, []string{"acme.exe", "acmehelper.exe"})
	plan, err = f.create(Request{Name: "ask", Action: "install", Version: "2.0", Scope: "machine", DeviceIDs: []uuid.UUID{dev},
		Prompts: &Prompts{InUse: "ask", AskTimeoutS: 120, Restart: "countdown", RestartNotifyMinutes: 10}})
	if err != nil {
		t.Fatal(err)
	}
	pr := body(plan).Prompts
	if pr == nil || pr.InUse != agentv1.InUseAction_IN_USE_ACTION_ASK || len(pr.Processes) != 2 || pr.Processes[0] != "acme.exe" ||
		pr.AskTimeoutS != 120 || pr.Restart != agentv1.RestartPrompt_RESTART_PROMPT_COUNTDOWN || pr.RestartNotifyMinutes != 10 {
		t.Fatalf("prompts in the job: %+v", pr)
	}
	var stored []byte
	if err := f.pool.QueryRow(t.Context(), "SELECT prompts FROM deployments WHERE id = $1", plan.DeploymentID).Scan(&stored); err != nil || ParsePrompts(stored) == nil {
		t.Fatalf("the deployment keeps its choice: %s %v", stored, err)
	}

	// A restart choice alone needs no program names and carries none.
	f.exec("DELETE FROM package_overrides")
	plan, err = f.create(Request{Name: "restart", Action: "install", Version: "2.0", Scope: "machine", DeviceIDs: []uuid.UUID{dev}, Prompts: &Prompts{Restart: "ask"}})
	if err != nil {
		t.Fatal(err)
	}
	if pr := body(plan).Prompts; pr == nil || len(pr.Processes) != 0 || pr.Restart != agentv1.RestartPrompt_RESTART_PROMPT_ASK || pr.InUse != agentv1.InUseAction_IN_USE_ACTION_IGNORE {
		t.Fatalf("restart only: %+v", pr)
	}
}

// The programs of a signed overlay are used when the administrator listed none, and the administrator's list wins.
func TestOverlayProgramsAreUsedUnderTheAdministratorsList(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	dev := f.device("pc", "amd64")
	f.rec.setOnline(dev)
	o := catalog.LoadOverlay()
	o.SetOrg(f.org, map[string]catalog.OverlayEntry{"custom.acmetool": {Identifier: "Custom.AcmeTool", Source: "Clinic IT", Processes: []string{"fromoverlay.exe"}}})
	f.svc.Overlay = o
	procs := func(name string) []string {
		plan, err := f.create(Request{Name: name, Action: "install", Version: "2.0", Scope: "machine", DeviceIDs: []uuid.UUID{dev}, Prompts: &Prompts{InUse: "close"}})
		if err != nil {
			t.Fatal(err)
		}
		return envOf(t, f.jobs(plan.DeploymentID)[0]).GetInstall().Prompts.Processes
	}
	if got := procs("a"); len(got) != 1 || got[0] != "fromoverlay.exe" {
		t.Fatalf("overlay: %v", got)
	}
	f.exec("INSERT INTO package_overrides (org_id, package_id, processes) VALUES ($1,$2,$3)", f.org, f.pkg.ID, []string{"mine.exe"})
	if got := procs("b"); len(got) != 1 || got[0] != "mine.exe" {
		t.Fatalf("the administrator's list must win: %v", got)
	}
}

func TestPromptsAreIgnoredForUninstall(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	dev := f.device("pc", "amd64")
	f.install(dev, "machine", "", "reg64", "AcmeTool", "1.0")
	if _, err := f.create(Request{Action: "uninstall", Scope: "machine", DeviceIDs: []uuid.UUID{dev}, Prompts: &Prompts{InUse: "close"}}); err != nil && errors.Is(err, ErrInvalid) {
		t.Fatalf("an uninstall has no prompts to check: %v", err)
	}
}
