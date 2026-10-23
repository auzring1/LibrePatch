package policies

import (
	"context"
	"crypto/sha256"
	"errors"
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
	"github.com/auzring1/librepatch/internal/shared/vercmp"
	"github.com/auzring1/librepatch/internal/testutil/pgtest"
)

type offline struct{}

func (offline) Offer(uuid.UUID, *agentv1.SignedEnvelope) bool { return false }

type fx struct {
	t      *testing.T
	pool   *pgxpool.Pool
	svc    *Service
	org    uuid.UUID
	user   uuid.UUID
	site   uuid.UUID
	pkg    uuid.UUID
	mu     sync.Mutex
	offset time.Duration
}

func (f *fx) now() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return time.Now().Add(f.offset) }
func (f *fx) advance(d time.Duration) {
	f.mu.Lock()
	f.offset += d
	f.mu.Unlock()
}

func newFx(t *testing.T) *fx {
	db := pgtest.New(t)
	h, err := pki.NewHierarchy("Test", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	auth := pki.NewAuthority(h.Root.Cert, h.Issuing, h.JobSigning)
	f := &fx{t: t, pool: db.Pool, org: uuid.New(), user: uuid.New(), site: uuid.New()}
	dep := &deploy.Service{Pool: db.Pool, Authority: func() *pki.Authority { return auth }, Dispatcher: offline{}, Now: f.now}
	f.svc = &Service{Pool: db.Pool, Deploy: dep, Now: f.now}
	f.exec("INSERT INTO organizations (id, name) VALUES ($1, 'o')", f.org)
	f.exec("INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, $3, 'A', 'x')", f.user, f.org, f.user.String()+"@example.com")
	f.exec("INSERT INTO sites (id, org_id, name) VALUES ($1, $2, 's')", f.site, f.org)
	f.catalog("2.0")
	return f
}

func (f *fx) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) count(sql string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fx) actor() Actor { return Actor{Org: f.org, User: f.user, IP: "127.0.0.1"} }

// catalog registers the package "Acme Tool" with one version (custom upload: no verification prompt).
func (f *fx) catalog(version string) {
	ctx := context.Background()
	q := dbq.New(f.pool)
	if f.pkg == uuid.Nil {
		pid, err := q.UpsertCatalogPackage(ctx, dbq.UpsertCatalogPackageParams{ID: uuid.New(), OrgID: f.org, Source: "custom", Identifier: "Custom.AcmeTool", Name: "Acme Tool", Publisher: "Acme"})
		if err != nil {
			f.t.Fatal(err)
		}
		f.pkg = pid
	}
	vid, err := q.UpsertCatalogVersion(ctx, dbq.UpsertCatalogVersionParams{ID: uuid.New(), PackageID: f.pkg, Version: version, VersionKey: vercmp.Key(version)})
	if err != nil {
		f.t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("x" + version))
	if err := q.InsertCatalogInstaller(ctx, dbq.InsertCatalogInstallerParams{ID: uuid.New(), VersionID: vid, Architecture: "x64", Scope: "machine", InstallerType: "msi",
		Url: "https://v.example/" + version + ".msi", Sha256: sum[:], FileName: "a.msi", Switches: []byte(`{"silent":[],"custom":[]}`),
		SuccessCodes: []int32{}, ExpectedCodes: []int32{}, Detection: []byte(`[]`)}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) device(host string, enrolled time.Time) uuid.UUID {
	id := uuid.New()
	f.exec("INSERT INTO devices (id, org_id, site_id, status, hostname, arch, enrolled_at) VALUES ($1,$2,$3,'active',$4,'amd64',$5)", id, f.org, f.site, host, enrolled)
	return id
}

func (f *fx) install(dev uuid.UUID, version string) {
	var title uuid.UUID
	err := f.pool.QueryRow(context.Background(), `INSERT INTO software_titles (id, org_id, normalized_name, normalized_publisher, display_name, display_publisher)
		VALUES ($1,$2,'acme tool','acme','Acme Tool','Acme') ON CONFLICT (org_id, normalized_name, normalized_publisher) DO UPDATE SET display_name = EXCLUDED.display_name
		RETURNING id`, uuid.New(), f.org).Scan(&title)
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO software_installs (device_id, source, scope, user_sid, item_key, title_id, name, version, version_key, first_seen_at, last_seen_at)
		VALUES ($1,'reg64','machine','','AcmeTool',$2,'Acme Tool',$3,$4,now(),now())`, dev, title, version, vercmp.Key(version))
}

func (f *fx) group(devs ...uuid.UUID) uuid.UUID {
	id := uuid.New()
	f.exec("INSERT INTO groups (id, org_id, name, kind, created_by) VALUES ($1,$2,$3,'static',$4)", id, f.org, "g"+id.String()[:6], f.user)
	for _, d := range devs {
		f.exec("INSERT INTO group_members (group_id, device_id) VALUES ($1,$2)", id, d)
	}
	return id
}

func (f *fx) policy(kind string, groups []uuid.UUID, mut func(*Input)) uuid.UUID {
	f.t.Helper()
	in := Input{Name: "p-" + uuid.NewString()[:6], Kind: kind, PackageID: f.pkg, GroupIDs: groups, Enabled: true, OnlyNewDevices: true}
	if mut != nil {
		mut(&in)
	}
	id, err := f.svc.Create(context.Background(), f.actor(), in)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *fx) jobsFor(dev uuid.UUID) int {
	return f.count("SELECT count(*) FROM jobs WHERE device_id=$1 AND type IN ('software_install','software_update')", dev)
}

func TestKeepUpdatedUpdatesOnlyOutdatedCopiesOnceAndRetriesLater(t *testing.T) {
	f := newFx(t)
	old, cur, none := f.device("old", time.Now()), f.device("cur", time.Now()), f.device("none", time.Now())
	f.install(old, "1.0")
	f.install(cur, "2.0")
	g := f.group(old, cur, none)
	f.policy("keep_updated", []uuid.UUID{g}, nil)
	ctx := context.Background()

	f.svc.Tick(ctx)
	if f.jobsFor(old) != 1 || f.jobsFor(cur) != 0 || f.jobsFor(none) != 0 {
		t.Fatalf("only the outdated copy gets an update: old=%d cur=%d none=%d", f.jobsFor(old), f.jobsFor(cur), f.jobsFor(none))
	}
	var action string
	f.pool.QueryRow(ctx, "SELECT d.action FROM deployments d JOIN jobs j ON j.deployment_id=d.id WHERE j.device_id=$1 LIMIT 1", old).Scan(&action)
	if action != "update" {
		t.Fatalf("action = %q", action)
	}
	// The deployment is audited as the policy (the system), not as the person who made the policy.
	if f.count("SELECT count(*) FROM audit_log WHERE action='deployment.create' AND actor_type='system' AND actor_id LIKE 'policy:%'") != 1 {
		t.Fatal("policy deployments must be audited as policy actions")
	}
	f.svc.Tick(ctx)
	if f.jobsFor(old) != 1 {
		t.Fatal("a device with a job in flight must not get a second one")
	}
	// The job fails; it is retried a day later, at most three times, then left alone.
	for i := 1; i <= 3; i++ {
		f.exec("UPDATE jobs SET status='failed' WHERE device_id=$1 AND status IN ('queued','sent')", old)
		f.advance(25 * time.Hour)
		f.svc.Tick(ctx)
		if f.jobsFor(old) != 1+i && i < 3 {
			t.Fatalf("retry %d: %d jobs", i, f.jobsFor(old))
		}
	}
	jobs := f.jobsFor(old)
	f.exec("UPDATE jobs SET status='failed' WHERE device_id=$1 AND status IN ('queued','sent')", old)
	f.advance(25 * time.Hour)
	f.svc.Tick(ctx)
	if f.jobsFor(old) != jobs {
		t.Fatalf("a device that failed three times is left alone: %d -> %d", jobs, f.jobsFor(old))
	}
}

func TestKeepUpdatedWaitsForTheDelayAndFollowsNewVersions(t *testing.T) {
	f := newFx(t)
	d := f.device("d", time.Now())
	f.install(d, "1.0")
	g := f.group(d)
	f.policy("keep_updated", []uuid.UUID{g}, func(in *Input) { in.DelayDays = 7 })
	ctx := context.Background()
	f.svc.Tick(ctx)
	if f.jobsFor(d) != 0 {
		t.Fatal("a version younger than the delay must wait")
	}
	f.advance(8 * 24 * time.Hour)
	f.svc.Tick(ctx)
	if f.jobsFor(d) != 1 {
		t.Fatal("after the delay the update goes out")
	}
	// A newer version resets the attempt: the device is updated again without waiting for retries.
	f.exec("UPDATE jobs SET status='succeeded' WHERE device_id=$1", d)
	f.install2(d, "2.0")
	f.catalog("3.0")
	f.exec("UPDATE catalog_versions SET imported_at = now() - interval '30 days' WHERE version='3.0'")
	f.advance(time.Hour)
	f.svc.Tick(ctx)
	if f.jobsFor(d) != 2 {
		t.Fatalf("a newer version must be rolled out: %d jobs", f.jobsFor(d))
	}
}

// install2 changes the installed version of the fixture package on a device.
func (f *fx) install2(dev uuid.UUID, version string) {
	f.exec("UPDATE software_installs SET version=$2, version_key=$3 WHERE device_id=$1", dev, version, vercmp.Key(version))
}

func TestBaselineInstallsOnNewDevicesOnly(t *testing.T) {
	f := newFx(t)
	existing := f.device("existing", time.Now().Add(-48*time.Hour))
	g := f.group(existing)
	f.policy("baseline", []uuid.UUID{g}, nil)
	ctx := context.Background()
	f.svc.Tick(ctx)
	if f.jobsFor(existing) != 0 {
		t.Fatal("a baseline for new devices must not touch devices enrolled before the policy")
	}
	f.advance(time.Minute)
	fresh := f.device("fresh", f.now().Add(time.Second))
	f.exec("INSERT INTO group_members (group_id, device_id) VALUES ($1,$2)", g, fresh)
	f.advance(time.Minute)
	f.svc.Tick(ctx)
	if f.jobsFor(fresh) != 1 {
		t.Fatal("a device that joined later must get the baseline")
	}
	f.svc.Tick(ctx)
	if f.jobsFor(fresh) != 1 {
		t.Fatal("once per device")
	}
	// A device that already has the software (any version) is left alone, even if new.
	f.advance(time.Minute)
	has := f.device("has", f.now().Add(time.Second))
	f.install(has, "1.0")
	f.exec("INSERT INTO group_members (group_id, device_id) VALUES ($1,$2)", g, has)
	f.advance(time.Minute)
	f.svc.Tick(ctx)
	if f.jobsFor(has) != 0 {
		t.Fatal("a baseline never reinstalls software that is present")
	}
	// All existing devices when the administrator asks for it.
	g2 := f.group(existing)
	f.policy("baseline", []uuid.UUID{g2}, func(in *Input) { in.OnlyNewDevices = false })
	f.svc.Tick(ctx)
	if f.jobsFor(existing) != 1 {
		t.Fatal("only_new_devices=false covers existing devices")
	}
}

func TestPolicyValidationAndManagement(t *testing.T) {
	f := newFx(t)
	d := f.device("d", time.Now())
	g := f.group(d)
	ctx := context.Background()
	bad := []Input{
		{Name: "", Kind: "baseline", PackageID: f.pkg, GroupIDs: []uuid.UUID{g}},
		{Name: "x", Kind: "nonsense", PackageID: f.pkg, GroupIDs: []uuid.UUID{g}},
		{Name: "x", Kind: "baseline", PackageID: f.pkg},
		{Name: "x", Kind: "baseline", PackageID: uuid.New(), GroupIDs: []uuid.UUID{g}},
		{Name: "x", Kind: "baseline", PackageID: f.pkg, GroupIDs: []uuid.UUID{uuid.New()}},
		{Name: "x", Kind: "baseline", PackageID: f.pkg, GroupIDs: []uuid.UUID{g}, DelayDays: 999},
		{Name: "x", Kind: "baseline", PackageID: f.pkg, GroupIDs: []uuid.UUID{g}, Window: &deploy.Window{StartMinute: 5000, DurationMinutes: 5}},
	}
	for i, in := range bad {
		if _, err := f.svc.Create(ctx, f.actor(), in); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: %v", i, err)
		}
	}
	id := f.policy("baseline", []uuid.UUID{g}, func(in *Input) { in.Name = "dup" })
	if _, err := f.svc.Create(ctx, f.actor(), Input{Name: "dup", Kind: "baseline", PackageID: f.pkg, GroupIDs: []uuid.UUID{g}}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	list, err := f.svc.List(ctx, f.org)
	if err != nil || len(list) != 1 || list[0].PackageName != "Acme Tool" {
		t.Fatalf("list: %v %+v", err, list)
	}
	if err := f.svc.Update(ctx, f.actor(), id, Input{Name: "dup", Kind: "keep_updated", PackageID: f.pkg, GroupIDs: []uuid.UUID{g}, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	// A disabled policy does nothing.
	f.install(d, "1.0")
	f.svc.Tick(ctx)
	if f.jobsFor(d) != 0 {
		t.Fatal("a disabled policy ran")
	}
	if err := f.svc.Delete(ctx, f.actor(), id); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Delete(ctx, f.actor(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	for _, a := range []string{"policy.create", "policy.update", "policy.delete"} {
		if f.count("SELECT count(*) FROM audit_log WHERE action=$1", a) == 0 {
			t.Errorf("no audit entry %s", a)
		}
	}
}

// A policy's choice about messages to the user reaches the jobs it creates, and needs the package's program names (D124).
func TestPolicyPromptsReachTheJobs(t *testing.T) {
	f := newFx(t)
	d := f.device("d", time.Now())
	f.install(d, "1.0")
	g := f.group(d)
	ctx := context.Background()
	in := Input{Name: "ask", Kind: "keep_updated", PackageID: f.pkg, GroupIDs: []uuid.UUID{g}, Enabled: true, Prompts: &deploy.Prompts{InUse: "ask", Restart: "ask"}}
	if _, err := f.svc.Create(ctx, f.actor(), in); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a package without program names: %v", err)
	}
	f.exec("INSERT INTO package_overrides (org_id, package_id, processes) VALUES ($1,$2,$3)", f.org, f.pkg, []string{"acme.exe"})
	in.Prompts.AskTimeoutS = 5
	if _, err := f.svc.Create(ctx, f.actor(), in); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a question that stays up 5 seconds: %v", err)
	}
	in.Prompts.AskTimeoutS = 90
	id, err := f.svc.Create(ctx, f.actor(), in)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := f.svc.List(ctx, f.org)
	if len(list) != 1 || list[0].ID != id || list[0].Prompts == nil || list[0].Prompts.InUse != "ask" || list[0].Prompts.AskTimeoutS != 90 {
		t.Fatalf("the policy keeps its choice: %+v", list)
	}
	f.svc.Tick(ctx)
	var raw []byte
	if err := f.pool.QueryRow(ctx, "SELECT body FROM jobs WHERE device_id=$1 AND type IN ('software_install','software_update')", d).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var env agentv1.JobEnvelope
	if err := proto.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	pr := env.GetInstall().GetPrompts()
	if pr == nil || pr.InUse != agentv1.InUseAction_IN_USE_ACTION_ASK || pr.Restart != agentv1.RestartPrompt_RESTART_PROMPT_ASK || len(pr.Processes) != 1 || pr.AskTimeoutS != 90 {
		t.Fatalf("prompts in the job: %+v", pr)
	}
	// Taking the choice away makes the policy silent again.
	in.Prompts = nil
	if err := f.svc.Update(ctx, f.actor(), id, in); err != nil {
		t.Fatal(err)
	}
	if list, _ = f.svc.List(ctx, f.org); list[0].Prompts != nil {
		t.Fatalf("silent again: %+v", list[0].Prompts)
	}
}

// installUser adds a copy of the fixture package installed for one person (not for the whole PC).
func (f *fx) installUser(dev uuid.UUID, version string) {
	var title uuid.UUID
	err := f.pool.QueryRow(context.Background(), `INSERT INTO software_titles (id, org_id, normalized_name, normalized_publisher, display_name, display_publisher)
		VALUES ($1,$2,'acme tool','acme','Acme Tool','Acme') ON CONFLICT (org_id, normalized_name, normalized_publisher) DO UPDATE SET display_name = EXCLUDED.display_name
		RETURNING id`, uuid.New(), f.org).Scan(&title)
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`INSERT INTO software_installs (device_id, source, scope, user_sid, item_key, title_id, name, version, version_key, first_seen_at, last_seen_at)
		VALUES ($1,'hku','user','S-1-5-21-1000','AcmeToolUser',$2,'Acme Tool',$3,$4,now(),now())`, dev, title, version, vercmp.Key(version))
}

// A policy sees what the Software updates page sees: a copy installed for one person is updated too, by a deployment of its own,
// and a device with both kinds of copy gets both (D143).
func TestKeepUpdatedAlsoUpdatesCopiesInstalledForOnePerson(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	f.userInstaller("2.0")
	perUser, both, current := f.device("peruser", time.Now()), f.device("both", time.Now()), f.device("current", time.Now())
	f.installUser(perUser, "1.0")
	f.install(both, "1.0")
	f.installUser(both, "1.0")
	f.install(current, "2.0")
	g := f.group(perUser, both, current)
	id := f.policy("keep_updated", []uuid.UUID{g}, func(in *Input) { in.OnlyNewDevices = false })
	f.svc.Tick(ctx)

	scopes := func(dev uuid.UUID) string {
		var s string
		f.pool.QueryRow(ctx, "SELECT coalesce(string_agg(DISTINCT d.scope, ','), '') FROM deployments d JOIN jobs j ON j.deployment_id=d.id WHERE j.device_id=$1", dev).Scan(&s)
		return s
	}
	if got := scopes(perUser); got != "user" {
		t.Fatalf("the per-user copy is updated by a user-scope deployment: %q", got)
	}
	if got := scopes(both); got != "machine,user" {
		t.Fatalf("a device with both gets both: %q", got)
	}
	if got := scopes(current); got != "" {
		t.Fatalf("a current device gets nothing: %q", got)
	}
	if p := f.listOne(id); p.State != StateUpdating || p.LastDeploymentID == nil {
		t.Fatalf("status: %+v", p)
	}
	f.svc.Tick(ctx)
	if f.count("SELECT count(*) FROM deployments") != 2 {
		t.Fatalf("a second check must not deploy again: %d deployments", f.count("SELECT count(*) FROM deployments"))
	}
}

// userInstaller gives the fixture package a per-user installer for a version, so copies installed for one person can be updated.
func (f *fx) userInstaller(version string) {
	ctx := context.Background()
	q := dbq.New(f.pool)
	var vid uuid.UUID
	if err := f.pool.QueryRow(ctx, "SELECT id FROM catalog_versions WHERE package_id=$1 AND version=$2", f.pkg, version).Scan(&vid); err != nil {
		f.t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("user" + version))
	if err := q.InsertCatalogInstaller(ctx, dbq.InsertCatalogInstallerParams{ID: uuid.New(), VersionID: vid, Architecture: "x64", Scope: "user", InstallerType: "exe",
		Url: "https://v.example/" + version + "-user.exe", Sha256: sum[:], FileName: "a-user.exe", Switches: []byte(`{"silent":["/S"],"custom":[]}`),
		SuccessCodes: []int32{}, ExpectedCodes: []int32{}, Detection: []byte(`[]`)}); err != nil {
		f.t.Fatal(err)
	}
}

// When the package has no installer for copies installed for one person, the PCs' own updates still go out and the
// device with only a per-user copy is recorded as a failed try (so it is retried a day later, not every five minutes).
func TestKeepUpdatedWithoutAUserInstallerStillUpdatesTheOthers(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	perUser, machine := f.device("peruser", time.Now()), f.device("machine", time.Now())
	f.installUser(perUser, "1.0")
	f.install(machine, "1.0")
	g := f.group(perUser, machine)
	f.policy("keep_updated", []uuid.UUID{g}, func(in *Input) { in.OnlyNewDevices = false })
	f.svc.Tick(ctx)
	if f.jobsFor(machine) != 1 || f.jobsFor(perUser) != 0 {
		t.Fatalf("machine=%d perUser=%d", f.jobsFor(machine), f.jobsFor(perUser))
	}
	var failures int32
	if err := f.pool.QueryRow(ctx, "SELECT failures FROM policy_attempts WHERE device_id=$1", perUser).Scan(&failures); err != nil || failures != 1 {
		t.Fatalf("a failed try is recorded: %v %d", err, failures)
	}
	f.svc.Tick(ctx)
	if f.count("SELECT count(*) FROM policy_attempts WHERE device_id=$1 AND failures=1", perUser) != 1 {
		t.Fatal("not retried at once")
	}
}
