package deploy

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
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
	"github.com/auzring1/librepatch/internal/server/catalog"
	"github.com/auzring1/librepatch/internal/server/pki"
	"github.com/auzring1/librepatch/internal/shared/envelope"
	"github.com/auzring1/librepatch/internal/shared/vercmp"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

type recorder struct {
	mu     sync.Mutex
	offers map[uuid.UUID][]*agentv1.SignedEnvelope
	online map[uuid.UUID]bool
}

func (r *recorder) setOnline(id uuid.UUID) {
	r.mu.Lock()
	r.online[id] = true
	r.mu.Unlock()
}

func (r *recorder) count(id uuid.UUID) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.offers[id])
}

func (r *recorder) Offer(id uuid.UUID, se *agentv1.SignedEnvelope) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.online[id] {
		return false
	}
	r.offers[id] = append(r.offers[id], se)
	return true
}

type fixture struct {
	t    *testing.T
	pool *pgxpool.Pool
	svc  *Service
	rec  *recorder
	h    *pki.Hierarchy
	org  uuid.UUID
	user uuid.UUID
	site uuid.UUID
	pkg  dbq.CatalogPackage
	ver  dbq.CatalogVersion
	now  time.Time
}

func newFixture(t *testing.T) *fixture {
	db := pgtest.New(t)
	h, err := pki.NewHierarchy("Test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	auth := pki.NewAuthority(h.Root.Cert, h.Issuing, h.JobSigning)
	rec := &recorder{offers: map[uuid.UUID][]*agentv1.SignedEnvelope{}, online: map[uuid.UUID]bool{}}
	f := &fixture{t: t, pool: db.Pool, rec: rec, h: h, org: uuid.New(), user: uuid.New(), site: uuid.New(), now: time.Now()}
	f.svc = &Service{Pool: db.Pool, Authority: func() *pki.Authority { return auth }, Dispatcher: rec}
	f.exec("INSERT INTO organizations (id, name) VALUES ($1, 'o')", f.org)
	f.exec("INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, $3, 'A', 'x')", f.user, f.org, f.user.String()+"@example.com")
	f.exec("INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 's')", f.site, f.org)
	return f
}

func (f *fixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) device(host, arch string) uuid.UUID {
	id := uuid.New()
	f.exec("INSERT INTO devices (id, org_id, site_id, status, hostname, arch) VALUES ($1,$2,$3,'active',$4,$5)", id, f.org, f.site, host, arch)
	return id
}

// install records a software row for the package's title on a device.
func (f *fixture) install(dev uuid.UUID, scope, sid, source, key, version string) {
	ctx := context.Background()
	var title uuid.UUID
	err := f.pool.QueryRow(ctx, `INSERT INTO software_titles (id, org_id, normalized_name, normalized_publisher, display_name, display_publisher)
		VALUES ($1,$2,'acme tool','acme','Acme Tool','Acme') ON CONFLICT (org_id, normalized_name, normalized_publisher) DO UPDATE SET display_name = EXCLUDED.display_name
		RETURNING id`, uuid.New(), f.org).Scan(&title)
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO software_installs (device_id, source, scope, user_sid, item_key, title_id, name, version, version_key, first_seen_at, last_seen_at)
		VALUES ($1,$2,$3,$4,$5,$6,'Acme Tool',$7,$8,now(),now())`, dev, source, scope, sid, key, title, version, vercmp.Key(version))
}

func (f *fixture) catalog(withUserInstaller bool) {
	ctx := context.Background()
	q := dbq.New(f.pool)
	pid, err := q.UpsertCatalogPackage(ctx, dbq.UpsertCatalogPackageParams{ID: uuid.New(), OrgID: f.org, Source: "custom", Identifier: "Custom.AcmeTool", Name: "Acme Tool", Publisher: "Acme"})
	if err != nil {
		f.t.Fatal(err)
	}
	vid, err := q.UpsertCatalogVersion(ctx, dbq.UpsertCatalogVersionParams{ID: uuid.New(), PackageID: pid, Version: "2.0", VersionKey: vercmp.Key("2.0")})
	if err != nil {
		f.t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("x"))
	ins := func(scope, typ string) {
		err := q.InsertCatalogInstaller(ctx, dbq.InsertCatalogInstallerParams{ID: uuid.New(), VersionID: vid, Architecture: "x64", Scope: scope, InstallerType: typ,
			Url: "https://v.example/" + scope + ".exe", Sha256: sum[:], FileName: scope + ".exe", Switches: []byte(`{"silent":[],"custom":[]}`),
			SuccessCodes: []int32{}, ExpectedCodes: []int32{}, Detection: []byte(`[]`)})
		if err != nil {
			f.t.Fatal(err)
		}
	}
	ins("machine", "msi")
	if withUserInstaller {
		ins("user", "inno")
	}
	f.pkg, _ = q.GetCatalogPackage(ctx, dbq.GetCatalogPackageParams{ID: pid, OrgID: f.org})
	f.ver, _ = q.GetCatalogVersion(ctx, dbq.GetCatalogVersionParams{ID: vid, OrgID: f.org})
}

func (f *fixture) policy(p string) {
	f.exec("INSERT INTO org_settings (org_id, user_scope_policy) VALUES ($1,$2) ON CONFLICT (org_id) DO UPDATE SET user_scope_policy = EXCLUDED.user_scope_policy", f.org, p)
}

func (f *fixture) create(r Request) (*Plan, error) {
	r.UserID, r.PackageID = f.user, f.pkg.ID
	if r.Name == "" {
		r.Name = "d"
	}
	plan, err := f.svc.Create(context.Background(), f.org, r)
	f.svc.Wait()
	return plan, err
}

func (f *fixture) jobs(dep uuid.UUID) []dbq.Job {
	rows, err := f.pool.Query(context.Background(), "SELECT id FROM jobs WHERE deployment_id = $1 ORDER BY created_at, id", dep)
	if err != nil {
		f.t.Fatal(err)
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	q := dbq.New(f.pool)
	var out []dbq.Job
	for _, id := range ids {
		j, err := q.GetJob(context.Background(), dbq.GetJobParams{ID: id, OrgID: f.org})
		if err != nil {
			f.t.Fatal(err)
		}
		out = append(out, j)
	}
	return out
}

func envOf(t *testing.T, j dbq.Job) *agentv1.JobEnvelope {
	var env agentv1.JobEnvelope
	if err := proto.Unmarshal(j.Body, &env); err != nil {
		t.Fatal(err)
	}
	return &env
}

const sidA, sidB = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"

func TestMachineInstallPlansPerArchitecture(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	x64, arm := f.device("a-x64", "amd64"), f.device("b-arm", "arm64")
	plan, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{x64, arm}})
	if err != nil {
		t.Fatal(err)
	}
	// the x64-only package runs on arm64 through emulation (x64 is a fallback), both devices get a job
	if plan.Jobs != 2 || len(plan.Skipped) != 0 {
		t.Fatalf("%+v", plan)
	}
	for _, j := range f.jobs(plan.DeploymentID) {
		env := envOf(t, j)
		b := env.GetInstall()
		if env.Type != agentv1.JobType_JOB_TYPE_SOFTWARE_INSTALL || b == nil || b.Scope != agentv1.InstallScope_INSTALL_SCOPE_MACHINE ||
			b.Installer.Type != agentv1.InstallerType_INSTALLER_TYPE_MSI || env.TargetUserSid != "" || env.DeploymentId != plan.DeploymentID.String() {
			t.Fatalf("envelope: %+v", env)
		}
		if j.Status != "queued" || !j.ExpiresAt.After(j.NotBefore) {
			t.Fatalf("job: %+v", j)
		}
	}
}

func TestUpdateOnlyTouchesOlderInstalls(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	old, cur, none := f.device("old", "amd64"), f.device("cur", "amd64"), f.device("none", "amd64")
	f.install(old, "machine", "", "reg64", "AcmeTool", "1.0")
	f.install(cur, "machine", "", "reg64", "AcmeTool", "2.0")
	plan, err := f.create(Request{Action: "update", Scope: "machine", DeviceIDs: []uuid.UUID{old, cur, none}})
	if err != nil {
		t.Fatal(err)
	}
	// the old copy's removal plus the update itself, both for the one device that has an older copy
	if plan.Jobs != 2 || len(plan.Skipped) != 2 {
		t.Fatalf("%+v", plan)
	}
	for _, j := range f.jobs(plan.DeploymentID) {
		if j.DeviceID != old {
			t.Fatalf("job for the wrong device: %+v", j)
		}
		if j.Type == "software_update" && !envOf(t, j).GetInstall().Update {
			t.Fatalf("%+v", j)
		}
	}
}

func TestUserScopeInstallTargetsEveryProfile(t *testing.T) {
	f := newFixture(t)
	f.catalog(true)
	d := f.device("pc", "amd64")
	f.exec("INSERT INTO device_users (device_id, sid, username, profile_path) VALUES ($1,$2,'alice','C:\\Users\\alice'), ($1,$3,'bob','C:\\Users\\bob'), ($1,'S-1-5-18','SYSTEM','')", d, sidA, sidB)
	plan, err := f.create(Request{Action: "install", Scope: "user", DeviceIDs: []uuid.UUID{d}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Jobs != 2 || plan.UserJobs != 2 {
		t.Fatalf("%+v", plan) // the SYSTEM entry has no profile and is skipped
	}
	for _, j := range f.jobs(plan.DeploymentID) {
		env := envOf(t, j)
		if (env.TargetUserSid != sidA && env.TargetUserSid != sidB) || env.GetInstall().Scope != agentv1.InstallScope_INSTALL_SCOPE_USER ||
			env.GetInstall().Installer.Type != agentv1.InstallerType_INSTALLER_TYPE_INNO {
			t.Fatalf("%+v", env)
		}
	}
}

func TestPerUserPolicies(t *testing.T) {
	cases := []struct {
		policy      string
		wantMachine int
		wantUser    int
		userType    string
		dependent   bool
		skipped     bool
	}{
		{"report_only", 1, 0, "", false, false},
		{"update_in_place", 1, 1, "software_update", false, false},
		{"convert_to_machine", 1, 1, "software_uninstall", true, false},
		{"remove", 1, 1, "software_uninstall", false, false},
	}
	for _, c := range cases {
		t.Run(c.policy, func(t *testing.T) {
			f := newFixture(t)
			f.catalog(true)
			f.policy(c.policy)
			d := f.device("pc", "amd64")
			f.install(d, "user", sidA, "hku", "AcmeUser", "1.0")
			plan, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{d}})
			if err != nil {
				t.Fatal(err)
			}
			if plan.PerUserFound != 1 || plan.PerUserPolicy != c.policy || plan.Jobs != c.wantMachine+c.wantUser {
				t.Fatalf("%+v", plan)
			}
			var machine, user *dbq.Job
			js := f.jobs(plan.DeploymentID)
			for i := range js {
				if js[i].UserSid == "" {
					machine = &js[i]
				} else {
					user = &js[i]
				}
			}
			if machine == nil || (c.wantUser == 1) != (user != nil) {
				t.Fatalf("jobs: %+v", js)
			}
			if user != nil {
				if user.Type != c.userType || user.UserSid != sidA {
					t.Fatalf("user job: %+v", user)
				}
				if c.dependent != (user.DependsOn != nil && *user.DependsOn == machine.ID) {
					t.Fatalf("dependency: %+v", user.DependsOn)
				}
				if c.userType == "software_uninstall" {
					u := envOf(t, *user).GetUninstall()
					if u.ItemSource != "hku" || u.ItemKey != "AcmeUser" || u.Scope != agentv1.InstallScope_INSTALL_SCOPE_USER {
						t.Fatalf("uninstall body: %+v", u)
					}
				}
			}
		})
	}
}

func TestPackageOverridePolicyBeatsOrgDefault(t *testing.T) {
	f := newFixture(t)
	f.catalog(true)
	f.policy("remove")
	f.exec("INSERT INTO package_overrides (org_id, package_id, user_scope_policy) VALUES ($1,$2,'report_only')", f.org, f.pkg.ID)
	d := f.device("pc", "amd64")
	f.install(d, "user", sidA, "hku", "AcmeUser", "1.0")
	plan, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{d}})
	if err != nil || plan.PerUserPolicy != "report_only" || plan.Jobs != 1 {
		t.Fatalf("%+v %v", plan, err)
	}
}

func TestUninstallJobsPerInstalledRow(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	d, other := f.device("pc", "amd64"), f.device("other", "amd64")
	f.install(d, "machine", "", "msi", "{11111111-2222-3333-4444-555555555555}", "1.0")
	f.install(d, "user", sidA, "hku", "AcmeUser", "1.0")
	plan, err := f.create(Request{Action: "uninstall", Scope: "machine", DeviceIDs: []uuid.UUID{d, other}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Jobs != 1 || len(plan.Skipped) != 1 {
		t.Fatalf("%+v", plan)
	}
	u := envOf(t, f.jobs(plan.DeploymentID)[0]).GetUninstall()
	if u.ItemSource != "msi" || u.ItemKey != "{11111111-2222-3333-4444-555555555555}" {
		t.Fatalf("%+v", u)
	}
	plan, err = f.create(Request{Action: "uninstall", Scope: "user", DeviceIDs: []uuid.UUID{d}})
	if err != nil || plan.Jobs != 1 || plan.UserJobs != 1 {
		t.Fatalf("%+v %v", plan, err)
	}
}

func TestGroupsResolveToDevices(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	a, b, c := f.device("a", "amd64"), f.device("b", "amd64"), f.device("c", "amd64")
	gid := uuid.New()
	f.exec("INSERT INTO groups (id, org_id, name, kind, created_by) VALUES ($1,$2,'static','static',$3)", gid, f.org, f.user)
	f.exec("INSERT INTO group_members (group_id, device_id) VALUES ($1,$2),($1,$3)", gid, a, b)
	f.exec("UPDATE devices SET status = 'revoked' WHERE id = $1", b) // revoked devices never get jobs
	plan, err := f.create(Request{Action: "install", Scope: "machine", GroupIDs: []uuid.UUID{gid}, DeviceIDs: []uuid.UUID{c}})
	if err != nil || plan.Devices != 2 || plan.Jobs != 2 {
		t.Fatalf("%+v %v", plan, err)
	}
	// dynamic group by hostname
	did := uuid.New()
	f.exec(`INSERT INTO groups (id, org_id, name, kind, filter, created_by) VALUES ($1,$2,'dyn','dynamic',
		'{"op":"device","field":"hostname","cmp":"prefix","value":"a"}',$3)`, did, f.org, f.user)
	plan, err = f.create(Request{Action: "install", Scope: "machine", GroupIDs: []uuid.UUID{did}})
	if err != nil || plan.Devices != 1 {
		t.Fatalf("%+v %v", plan, err)
	}
	// nothing matches -> error; another org's group id -> error
	if _, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{uuid.New()}}); !errors.Is(err, ErrNoTargets) {
		t.Fatalf("%v", err)
	}
	if _, err := f.create(Request{Action: "install", Scope: "machine", GroupIDs: []uuid.UUID{uuid.New()}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("%v", err)
	}
}

func TestUnverifiedWingetNeedsConfirmation(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	f.exec("UPDATE catalog_packages SET source = 'winget' WHERE id = $1", f.pkg.ID)
	d := f.device("pc", "amd64")
	if _, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{d}}); !errors.Is(err, ErrUnverified) {
		t.Fatalf("%v", err)
	}
	if _, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{d}, UnverifiedConfirmed: true}); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = 'deployment.create' AND details->>'unverified_confirmed' = 'true'`).Scan(&n)
	if n != 1 {
		t.Fatalf("the confirmation must be audited (found %d)", n)
	}

	// Once an administrator has marked the package verified, no confirmation is asked for.
	f.exec("UPDATE catalog_packages SET verified = true, verified_by_org = true WHERE id = $1", f.pkg.ID)
	d2 := f.device("pc2", "amd64")
	if _, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{d2}}); err != nil {
		t.Fatalf("a verified package must deploy without confirmation: %v", err)
	}
}

func TestDispatchSignsVerifiableEnvelopes(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	d := f.device("pc", "amd64")
	if _, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{d}, Window: &Window{Days: []int{1, 2}, StartMinute: 22 * 60, DurationMinutes: 120}}); err != nil {
		t.Fatal(err)
	}
	if f.rec.count(d) != 0 {
		t.Fatal("offered to an offline device")
	}
	f.rec.setOnline(d)
	f.svc.Dispatch(context.Background(), d)
	offers := f.rec.offers[d]
	if len(offers) != 1 {
		t.Fatalf("offers: %d", len(offers))
	}
	v := &envelope.Verifier{Root: f.h.Root.Cert, DeviceID: d.String(), OrgID: f.org.String(), SigningCerts: []*x509.Certificate{f.h.JobSigning.Cert}, Now: time.Now}
	env, err := v.Open(offers[0])
	if err != nil {
		t.Fatalf("the agent could not verify the envelope: %v", err)
	}
	if env.Window == nil || env.Window.StartMinute != 22*60 || len(env.Window.Days) != 2 || len(env.Nonce) != 16 {
		t.Fatalf("%+v", env)
	}
	// A job that is due now must not wait for a device whose clock is a little behind the server's: "not before" is
	// moved back by the skew the verifier already tolerates.
	if limit := time.Now().Add(-envelope.ClockSkew + time.Minute).Unix(); env.NotBefore > limit {
		t.Fatalf("not_before %d is not backdated by the clock skew (limit %d)", env.NotBefore, limit)
	}
	// dispatching again re-signs the same job (new nonce, same job id) until the agent acknowledges it
	f.svc.Dispatch(context.Background(), d)
	if f.rec.count(d) != 2 {
		t.Fatalf("unacknowledged jobs must be re-offered: %d", f.rec.count(d))
	}
	env2, _ := v.Open(f.rec.offers[d][1])
	if env2.JobId != env.JobId || string(env2.Nonce) == string(env.Nonce) {
		t.Fatal("re-offer must keep the job id and use a fresh nonce")
	}
}

func TestApplyUpdateStateMachineAndDependencies(t *testing.T) {
	f := newFixture(t)
	f.catalog(true)
	f.policy("convert_to_machine")
	d := f.device("pc", "amd64")
	f.install(d, "user", sidA, "hku", "AcmeUser", "1.0")
	f.rec.setOnline(d)
	plan, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{d}})
	if err != nil {
		t.Fatal(err)
	}
	js := f.jobs(plan.DeploymentID)
	var machine, user dbq.Job
	for _, j := range js {
		if j.UserSid == "" {
			machine = j
		} else {
			user = j
		}
	}
	// only the machine job is dispatched; the dependent uninstall waits
	if n := f.rec.count(d); n != 1 {
		t.Fatalf("offers before success: %d", n)
	}
	dev, _ := dbq.New(f.pool).GetDevice(context.Background(), d)
	apply := func(id uuid.UUID, st agentv1.JobState, res *agentv1.JobResult) {
		t.Helper()
		if err := f.svc.ApplyUpdate(context.Background(), dev, &agentv1.JobUpdate{JobId: id.String(), State: st, Result: res}); err != nil {
			t.Fatal(err)
		}
	}
	status := func(id uuid.UUID) string {
		j, _ := dbq.New(f.pool).GetJob(context.Background(), dbq.GetJobParams{ID: id, OrgID: f.org})
		return j.Status
	}
	apply(machine.ID, agentv1.JobState_JOB_STATE_ACCEPTED, nil)
	apply(machine.ID, agentv1.JobState_JOB_STATE_RUNNING, nil)
	if status(machine.ID) != "running" {
		t.Fatal(status(machine.ID))
	}
	apply(machine.ID, agentv1.JobState_JOB_STATE_SUCCEEDED, &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS, DetectionPassed: true,
		Message: "ok", LogTail: "log\x00text", InstalledVersion: "2.0"})
	if status(machine.ID) != "succeeded" {
		t.Fatal(status(machine.ID))
	}
	// a late "running" report must not reopen a finished job
	apply(machine.ID, agentv1.JobState_JOB_STATE_RUNNING, nil)
	if status(machine.ID) != "succeeded" {
		t.Fatal("a final job was reopened")
	}
	// success releases the dependent user-scope uninstall
	if n := f.rec.count(d); n != 2 {
		t.Fatalf("dependent job not dispatched after success: %d offers", n)
	}
	apply(user.ID, agentv1.JobState_JOB_STATE_SUCCEEDED, &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_SUCCESS})
	var dstatus string
	_ = f.pool.QueryRow(context.Background(), "SELECT status FROM deployments WHERE id = $1", plan.DeploymentID).Scan(&dstatus)
	if dstatus != "completed" {
		t.Fatalf("deployment status %s", dstatus)
	}
	// NUL bytes from the agent never reach the database
	var logTail string
	_ = f.pool.QueryRow(context.Background(), "SELECT result->>'log_tail' FROM jobs WHERE id = $1", machine.ID).Scan(&logTail)
	if logTail != "logtext" {
		t.Fatalf("log tail %q", logTail)
	}
	// a device cannot report on another device's job
	other := f.device("other", "amd64")
	odev, _ := dbq.New(f.pool).GetDevice(context.Background(), other)
	if err := f.svc.ApplyUpdate(context.Background(), odev, &agentv1.JobUpdate{JobId: machine.ID.String(), State: agentv1.JobState_JOB_STATE_FAILED}); !errors.Is(err, ErrUnknownJob) {
		t.Fatalf("cross-device update accepted: %v", err)
	}
}

func TestFailedMachineJobCancelsDependents(t *testing.T) {
	f := newFixture(t)
	f.catalog(true)
	f.policy("convert_to_machine")
	d := f.device("pc", "amd64")
	f.install(d, "user", sidA, "hku", "AcmeUser", "1.0")
	plan, _ := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{d}})
	dev, _ := dbq.New(f.pool).GetDevice(context.Background(), d)
	var machine, user dbq.Job
	for _, j := range f.jobs(plan.DeploymentID) {
		if j.UserSid == "" {
			machine = j
		} else {
			user = j
		}
	}
	if err := f.svc.ApplyUpdate(context.Background(), dev, &agentv1.JobUpdate{JobId: machine.ID.String(), State: agentv1.JobState_JOB_STATE_FAILED,
		Result: &agentv1.JobResult{Outcome: agentv1.JobOutcome_JOB_OUTCOME_FAILED, ExitCode: 1603}}); err != nil {
		t.Fatal(err)
	}
	u, _ := dbq.New(f.pool).GetJob(context.Background(), dbq.GetJobParams{ID: user.ID, OrgID: f.org})
	if u.Status != "cancelled" || u.StatusReason != "dependency_failed" {
		t.Fatalf("dependent job: %s %s (the per-user copy must not be removed when the machine install failed)", u.Status, u.StatusReason)
	}
}

func TestCancelDeploymentAndSweepAndRetry(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	d := f.device("pc", "amd64")
	plan, _ := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{d}})
	ctx := context.Background()
	if err := f.svc.CancelDeployment(ctx, f.org, f.user, plan.DeploymentID, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	js := f.jobs(plan.DeploymentID)
	if js[0].Status != "cancelled" {
		t.Fatal(js[0].Status)
	}
	// retry a cancelled job -> new attempt, deployment active again
	nid, err := f.svc.Retry(ctx, f.org, f.user, js[0].ID, "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	nj, _ := dbq.New(f.pool).GetJob(ctx, dbq.GetJobParams{ID: nid, OrgID: f.org})
	if nj.Attempt != 2 || nj.Status != "queued" || envOf(t, nj).JobId != nid.String() || envOf(t, nj).Attempt != 2 {
		t.Fatalf("%+v", nj)
	}
	if _, err := f.svc.Retry(ctx, f.org, f.user, nid, ""); !errors.Is(err, ErrNotRetryable) {
		t.Fatalf("a queued job is not retryable: %v", err)
	}
	f.svc.Wait() // the retry's background dispatch reads the clock
	// expiry sweep
	f.svc.Now = func() time.Time { return time.Now().Add(100 * 24 * time.Hour) }
	f.svc.Sweep(ctx)
	nj, _ = dbq.New(f.pool).GetJob(ctx, dbq.GetJobParams{ID: nid, OrgID: f.org})
	if nj.Status != "expired" {
		t.Fatalf("not expired: %s", nj.Status)
	}
}

func TestSelfUpdatingAppsAreLeftToTheVendorUnlessEnforced(t *testing.T) {
	f := newFixture(t)
	f.catalog(true)
	f.exec("UPDATE catalog_packages SET self_updating = true WHERE id = $1", f.pkg.ID)
	d := f.device("pc", "amd64")
	f.install(d, "machine", "", "reg64", "AcmeTool", "1.0")

	// An explicit update is refused...
	if _, err := f.create(Request{Action: "update", Scope: "machine", DeviceIDs: []uuid.UUID{d}}); !errors.Is(err, ErrSelfUpdating) {
		t.Fatalf("update of a self-updating app: %v", err)
	}
	// ...a fresh install is not an update and still works...
	if plan, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{d}}); err != nil || plan.Jobs != 1 {
		t.Fatalf("install: %+v %v", plan, err)
	}
	// ...and the per-user "update in place" policy leaves the app's own updater in charge.
	f.policy("update_in_place")
	f.install(d, "user", sidA, "hku", "AcmeUser", "1.0")
	plan, err := f.create(Request{Action: "install", Scope: "machine", DeviceIDs: []uuid.UUID{d}})
	if err != nil || plan.Jobs != 1 || len(plan.Skipped) != 1 {
		t.Fatalf("in-place update of a self-updating app: %+v %v", plan, err)
	}
	// An administrator can enforce versions anyway.
	f.exec("INSERT INTO package_overrides (org_id, package_id, self_update_policy) VALUES ($1,$2,'enforce')", f.org, f.pkg.ID)
	if plan, err := f.create(Request{Action: "update", Scope: "machine", DeviceIDs: []uuid.UUID{d}}); err != nil || plan.Jobs != 3 { // removal of the old copy + machine update + per-user copy
		t.Fatalf("enforced update: %+v %v", plan, err)
	}
}

func TestUpdateRemovesOlderCopiesBeforeInstalling(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	d := f.device("pc", "amd64")
	// 1.0 installed under a different Uninstall key than the new installer registers (the 7-Zip EXE -> MSI case),
	// plus 1.5 under yet another key, plus one already at the target.
	f.install(d, "machine", "", "reg64", "AcmeOld", "1.0")
	f.install(d, "machine", "", "reg64", "AcmeMid", "1.5")
	f.install(d, "machine", "", "reg64", "AcmeNew", "2.0")
	f.rec.setOnline(d)
	plan, err := f.create(Request{Action: "update", Scope: "machine", DeviceIDs: []uuid.UUID{d}})
	if err != nil || plan.Jobs != 3 {
		t.Fatalf("%+v %v", plan, err)
	}
	var rm1, rm2, up dbq.Job
	for _, j := range f.jobs(plan.DeploymentID) {
		switch {
		case j.Type == "software_update":
			up = j
		case envOf(t, j).GetUninstall().ItemKey == "AcmeOld":
			rm1 = j
		default:
			rm2 = j
		}
	}
	if envOf(t, rm1).GetUninstall().RemoveOlderThan != "2.0" || envOf(t, rm2).GetUninstall().ItemKey != "AcmeMid" {
		t.Fatalf("cleanup bodies: %+v %+v", envOf(t, rm1).GetUninstall(), envOf(t, rm2).GetUninstall())
	}
	// chain: remove 1.0 -> remove 1.5 -> update; every link runs even if the one before it failed
	if rm1.DependsOn != nil || rm2.DependsOn == nil || *rm2.DependsOn != rm1.ID || up.DependsOn == nil || *up.DependsOn != rm2.ID {
		t.Fatalf("chain: %v %v %v", rm1.DependsOn, rm2.DependsOn, up.DependsOn)
	}
	if rm2.DependsWhen != "finished" || up.DependsWhen != "finished" {
		t.Fatalf("modes: %s %s", rm2.DependsWhen, up.DependsWhen)
	}
	if n := f.rec.count(d); n != 1 {
		t.Fatalf("only the first removal may be offered at once, got %d", n)
	}
	dev, _ := dbq.New(f.pool).GetDevice(context.Background(), d)
	apply := func(id uuid.UUID, st agentv1.JobState) {
		t.Helper()
		if err := f.svc.ApplyUpdate(context.Background(), dev, &agentv1.JobUpdate{JobId: id.String(), State: st,
			Result: &agentv1.JobResult{ExitCode: 1}}); err != nil {
			t.Fatal(err)
		}
	}
	apply(rm1.ID, agentv1.JobState_JOB_STATE_FAILED) // a failed removal must not block the update
	if n := f.rec.count(d); n != 2 {
		t.Fatalf("second removal not offered after a failure of the first: %d", n)
	}
	apply(rm2.ID, agentv1.JobState_JOB_STATE_SUCCEEDED)
	if n := f.rec.count(d); n != 3 {
		t.Fatalf("update not offered after the removals: %d", n)
	}
}

func TestUpdateKeepsCopiesTheNewInstallerReplacesInPlace(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	// the new installer registers under "AcmeOld": it upgrades that copy itself
	f.exec(`UPDATE catalog_installers SET detection = '[{"kind":"registry","key":"AcmeOld","version":"2.0","cmp":"ge"}]'`)
	d := f.device("pc", "amd64")
	f.install(d, "machine", "", "reg64", "AcmeOld", "1.0")
	plan, err := f.create(Request{Action: "update", Scope: "machine", DeviceIDs: []uuid.UUID{d}})
	if err != nil || plan.Jobs != 1 {
		t.Fatalf("%+v %v", plan, err)
	}
	if j := f.jobs(plan.DeploymentID)[0]; j.Type != "software_update" || j.DependsOn != nil {
		t.Fatalf("%+v", j)
	}
}

func TestDeviceUpdatesListsOlderInstallsWithAvailableVersion(t *testing.T) {
	f := newFixture(t)
	f.catalog(false) // Acme Tool 2.0
	old, cur, other := f.device("old", "amd64"), f.device("cur", "amd64"), f.device("other", "amd64")
	f.install(old, "machine", "", "reg64", "AcmeTool", "1.0")
	f.install(cur, "machine", "", "reg64", "AcmeTool", "2.0")
	_ = other
	ups, err := f.svc.DeviceUpdates(context.Background(), f.org, old)
	if err != nil || len(ups) != 1 || ups[0].InstalledVersion != "1.0" || ups[0].LatestVersion != "2.0" || !ups[0].Deployable || ups[0].PackageID != f.pkg.ID {
		t.Fatalf("%+v %v", ups, err)
	}
	if ups, _ := f.svc.DeviceUpdates(context.Background(), f.org, cur); len(ups) != 0 {
		t.Fatalf("a current install is not an update: %+v", ups)
	}
	// A pin below the installed version hides the update; a self-updating app is listed but not deployable.
	f.exec("INSERT INTO package_overrides (org_id, package_id, pin) VALUES ($1,$2,'< 1.0')", f.org, f.pkg.ID)
	if ups, _ := f.svc.DeviceUpdates(context.Background(), f.org, old); len(ups) != 0 {
		t.Fatalf("pin ignored: %+v", ups)
	}
	f.exec("UPDATE package_overrides SET pin = ''")
	f.exec("UPDATE catalog_packages SET self_updating = true WHERE id = $1", f.pkg.ID)
	if ups, _ := f.svc.DeviceUpdates(context.Background(), f.org, old); len(ups) != 1 || ups[0].Deployable || ups[0].Reason == "" {
		t.Fatalf("self-updating: %+v", ups)
	}
}

func TestFleetUpdatesGroupsOlderInstallsByPackage(t *testing.T) {
	f := newFixture(t)
	f.catalog(false) // Acme Tool 2.0
	a, b, cur := f.device("a-pc", "amd64"), f.device("b-pc", "amd64"), f.device("lp-pc", "amd64")
	f.install(a, "machine", "", "reg64", "AcmeTool", "1.0")
	f.install(b, "machine", "", "reg64", "AcmeTool", "1.5")
	f.install(cur, "machine", "", "reg64", "AcmeTool", "2.0")
	ups, err := f.svc.FleetUpdates(context.Background(), f.org)
	if err != nil || len(ups) != 1 {
		t.Fatalf("%+v %v", ups, err)
	}
	u := ups[0]
	if u.PackageID != f.pkg.ID || u.LatestVersion != "2.0" || !u.Deployable || len(u.Devices) != 2 || u.Devices[0].Hostname != "a-pc" || u.Devices[1].InstalledVersion != "1.5" {
		t.Fatalf("%+v", u)
	}
	// Only active devices count: a revoked one is not a target.
	f.exec("UPDATE devices SET status = 'revoked' WHERE id = $1", b)
	if ups, _ := f.svc.FleetUpdates(context.Background(), f.org); len(ups) != 1 || len(ups[0].Devices) != 1 {
		t.Fatalf("revoked device listed: %+v", ups)
	}
	// A pin below every installed version hides the package; a self-updating app is listed but not deployable.
	f.exec("INSERT INTO package_overrides (org_id, package_id, pin) VALUES ($1,$2,'< 1.0')", f.org, f.pkg.ID)
	if ups, _ := f.svc.FleetUpdates(context.Background(), f.org); len(ups) != 0 {
		t.Fatalf("pin ignored: %+v", ups)
	}
	f.exec("UPDATE package_overrides SET pin = ''")
	f.exec("UPDATE catalog_packages SET self_updating = true WHERE id = $1", f.pkg.ID)
	if ups, _ := f.svc.FleetUpdates(context.Background(), f.org); len(ups) != 1 || ups[0].Deployable || ups[0].Reason == "" {
		t.Fatalf("self-updating: %+v", ups)
	}
}

func TestUninstallSoftwareRefusesSystemComponentsAndUnknownRows(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	d := f.device("pc", "amd64")
	f.install(d, "machine", "", "reg64", "AcmeTool", "1.0")
	f.install(d, "machine", "", "reg64", "AcmeRuntime", "1.0")
	f.exec("UPDATE software_installs SET system_component = true WHERE item_key = 'AcmeRuntime'")
	f.exec("UPDATE devices SET online = true WHERE id = $1", d)
	res, err := f.svc.UninstallSoftware(context.Background(), f.org, f.user, d, "127.0.0.1", []SoftwareRef{
		{Source: "reg64", Scope: "machine", ItemKey: "AcmeTool"},
		{Source: "reg64", Scope: "machine", ItemKey: "AcmeRuntime"},
		{Source: "reg64", Scope: "machine", ItemKey: "Missing"},
	})
	f.svc.Wait()
	if err != nil || len(res.JobIDs) != 1 || len(res.Skipped) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	var typ, title string
	_ = f.pool.QueryRow(context.Background(), "SELECT type, title FROM jobs WHERE id = $1", res.JobIDs[0]).Scan(&typ, &title)
	if typ != "software_uninstall" || !strings.Contains(title, "Acme Tool") {
		t.Fatalf("%s %s", typ, title)
	}
	if _, err := f.svc.UninstallSoftware(context.Background(), f.org, f.user, d, "x", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty request: %v", err)
	}
	// Another organization's device is not reachable.
	if _, err := f.svc.UninstallSoftware(context.Background(), uuid.New(), f.user, d, "x", []SoftwareRef{{Source: "reg64", Scope: "machine", ItemKey: "AcmeTool"}}); !errors.Is(err, ErrNotActive) {
		t.Fatalf("cross-org: %v", err)
	}
}

// A signed overlay's silent arguments and detection rules reach the signed job, under the administrator's own override
// (D122).
func TestOverlaySilentArgumentsReachTheSignedJob(t *testing.T) {
	f := newFixture(t)
	f.catalog(false)
	dev := f.device("pc", "amd64")
	f.rec.setOnline(dev)
	o := catalog.LoadOverlay()
	o.SetOrg(f.org, map[string]catalog.OverlayEntry{"custom.acmetool": {Identifier: "Custom.AcmeTool", Source: "Clinic IT", SilentArgs: []string{"/quiet", "/norestart"},
		ExtraDetection: []catalog.Detection{{Kind: "registry", Key: `HKLM\SOFTWARE\Acme`}}}})
	f.svc.Overlay = o

	argsOf := func(plan *Plan) ([]string, int) {
		jobs := f.jobs(plan.DeploymentID)
		if len(jobs) != 1 {
			t.Fatalf("jobs: %d", len(jobs))
		}
		b := envOf(t, jobs[0]).GetInstall()
		return b.Installer.Args, len(b.Detection)
	}
	plan, err := f.create(Request{Action: "install", Version: "2.0", Scope: "machine", DeviceIDs: []uuid.UUID{dev}})
	if err != nil {
		t.Fatal(err)
	}
	args, det := argsOf(plan)
	if len(args) != 2 || args[0] != "/quiet" || det < 1 {
		t.Fatalf("the overlay's arguments and detection must be in the job: %v, %d rules", args, det)
	}

	// The administrator's own silent arguments win over the overlay's.
	f.exec("INSERT INTO package_overrides (org_id, package_id, silent_args) VALUES ($1,$2,$3)", f.org, f.pkg.ID, []string{"/mine"})
	plan, err = f.create(Request{Action: "install", Version: "2.0", Scope: "machine", DeviceIDs: []uuid.UUID{dev}, Name: "again"})
	if err != nil {
		t.Fatal(err)
	}
	if args, _ := argsOf(plan); len(args) != 1 || args[0] != "/mine" {
		t.Fatalf("the administrator's override must win: %v", args)
	}
}
