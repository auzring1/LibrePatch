# Architecture

Status: Phases 1–3 implemented (see §0). Sections marked *(Phase N)* are built in that phase.

## 0. Implementation status (Phases 1–5)

| Area | State | Where |
|---|---|---|
| Server skeleton, config (secrets only via `*_FILE` outside dev mode) | ✅ | `cmd/librepatch-server`, `internal/server/{app,config}` |
| PostgreSQL schema, embedded goose migrations, owner/app role split | ✅ | `db/migrations`, `internal/server/store` |
| Internal CA: passphrase-sealed root, KEK-sealed issuing + job-signing + gateway keys | ✅ | `internal/server/pki`, `internal/server/kek` |
| First-run setup (one-time token, admin, mandatory TOTP, recovery codes, CA creation) | ✅ | `internal/server/api/setup.go` |
| Login + MFA, sessions, CSRF, CSP, rate limits, lockout, RBAC skeleton | ✅ | `internal/server/{auth,api}` |
| Hash-chained append-only audit log + CLI verifier | ✅ | `internal/server/audit` |
| Enrollment (tokens, approval, re-enrollment guard), mTLS gateway, revocation, renewal | ✅ | `internal/server/gateway` |
| Signed job envelopes (library + agent verification + replay ledger) | ✅ (no jobs are issued until Phase 3) | `internal/shared/envelope` |
| Agent: service, install/uninstall, CNG/TPM key, enrollment, heartbeat, hardware inventory | ✅ | `cmd/librepatch-agent`, `internal/agent/*` |
| Web console: setup, login/MFA, devices (live), enrollment tokens, audit | ✅ | `web/` |
| docker-compose (Caddy, server, Postgres), hardened | ✅ | `deploy/` |
| **Phase 2:** software inventory (registry 64/32, per-user, offline hives, MSI, AppX, portable), delta/resync protocol, change watchers | ✅ (Windows collectors verified by the Windows CI job) | `internal/agent/inventory` |
| **Phase 2:** BitLocker status, device users/profiles | ✅ | `internal/agent/hardware/bitlocker_windows.go`, `internal/agent/inventory/profiles.go` |
| **Phase 2:** server ingest, title normalization, version keys, history | ✅ | `internal/server/{inventory,gateway}`, `internal/shared/vercmp` |
| **Phase 2:** fleet software search, device detail page, dynamic groups, CSV export | ✅ | `internal/server/{api,groups}`, `web/` |
| **Phase 3:** catalog (winget-pkgs import, custom upload, overrides, verified overlay, self-updating marks) | ✅ | `internal/server/catalog`, `api/openapi.yaml` |
| **Phase 3:** deployments (targets, schedule, window, expiry), signed typed jobs, dispatch/re-offer, result tracking, retry/cancel, SSE | ✅ | `internal/server/{deploy,gateway}` |
| **Phase 3:** agent job engine (verify, persist, window/not-before/logon scheduling, download + hash + Authenticode, install/uninstall, detection, retries) | ✅ on Linux fakes; Windows-only parts compile and are exercised by the Windows CI `deploy` job, not yet on real VMs | `internal/agent/jobs` |
| **Phase 3:** user-context helper and logon queue | ⚠️ implemented, **unverified on a real multi-user Windows machine** | `internal/agent/jobs/helper*.go`, `winsvc` |
| **Phase 3:** web console (catalog, package overrides, deployment wizard, live job results, static groups, settings) | ✅ | `web/` |
| **Phase 3:** VM test matrix | ⚠️ harness only; no package is verified yet | `test/vm-matrix` |
| **Phase 4:** Windows Update on the agent (WUA COM scan/download/install/hide, policy detection, pending-reboot detection, daily autonomous scan, snapshot reporting) | ✅ on the Linux dev client; the COM code compiles and vets for Windows but is **unverified on a real machine** | `internal/agent/wu`, `internal/agent/jobs/wujobs.go` |
| **Phase 4:** reboot policy (never / outside active hours / deadline, visible countdown, persisted plan) | ⚠️ logic tested with fakes; the real `InitiateSystemShutdownEx` countdown is **unverified on a real machine** | `internal/agent/jobs`, `internal/agent/wu` |
| **Phase 4:** update catalog, approvals, auto-approval rules, rings with soak and success thresholds, holds, retry limits, conflict report | ✅ | `internal/server/updates`, `db/migrations/00005_windows_update.sql` |
| **Phase 4:** web console (Windows updates, Update policy, device "Windows updates" tab, restart) | ✅ | `web/` |
| **Phase 5:** agent self-update (vendor-signed release manifest, A/B slots, health confirmation, automatic rollback), release store and pilot-then-everyone rollout | ✅ Linux end to end (`TestAgentSelfUpdateEndToEnd`); the Windows service/scheduled-task mechanics (`internal/agent/selfupdate/platform_windows.go`) are **unverified on a real machine** | `internal/shared/release`, `internal/agent/{selfupdate,jobs}`, `internal/server/agentrel`, `cmd/librepatch-release` |
| **Phase 5:** users, sites, roles scoped to the organization or a site, forced password change, API tokens with scopes, security keys (WebAuthn) as a second factor | ✅ (browser test drives a virtual security key); real hardware keys not tried | `internal/server/{auth,api}`, `web/` |
| **Phase 5:** software policies (keep updated / baseline for new devices), patch-compliance reports, audit filters, chain verification and CSV export | ✅ | `internal/server/policies`, `internal/server/api/{policies,auditapi}.go` |
| **Phase 6:** load generator `cmd/librepatch-loadsim` (simulated agents with the real enrollment, mTLS channel, inventory, heartbeat and signed-job protocol; steady, storm and churn scenarios) and `scripts/loadtest.sh`; first measurements with up to 10,000 agents in a 4-CPU sandbox, and the server defects it found | ✅ procedure and numbers in [LOADTEST.md](LOADTEST.md); **not a capacity statement** | `cmd/librepatch-loadsim`, `internal/loadsim`, `scripts/loadtest.sh`, `test/e2e/loadsim_test.go` |
| **Phase 5:** encrypted backup and restore (`librepatch-server backup`/`restore`, age) | ✅ tested against PostgreSQL 16, small data | `internal/server/backup` |
| **Phase 5:** agent MSI (WiX 7) | ⚠️ sources, tests of the sources and a CI job; **never built or run** (WiX cannot bind an MSI on Linux) | `installer/windows` |

Implementation notes that refine the design below:
- **REST layer (D6, revised):** handlers are hand-written with strict JSON decoding. `api/openapi.yaml` is the contract, and `TestRoutesMatchSpec` fails the build if routes and spec drift. TypeScript types are generated from the spec.
- **Web console CSP:** `index.html` carries a placeholder nonce that the server replaces per request. Mantine and `react-remove-scroll` (through `get-nonce`) put that nonce on every injected `<style>`. The Playwright test fails on any CSP violation.
- **Agent state:** `status.json` in the data directory reports `enrolling`, `pending_approval`, `connected`, `rejected` or `error`, for `install`, `status` and support staff.
- **Renewal:** the agent checks renewal on a timer scaled to certificate lifetime (lifetime/10, clamped to 1 s–1 h). It uses server-corrected time, and lifetime excludes the CA's 5-minute backdate (`pkix.CertBackdate`).
- **Phase 3 as built (differences from §5–§8, with the decision numbers in DECISIONS.md):**
  - *Catalog source* is the winget-pkgs repository (manifests on import), not the CDN index (D41). Search = imported packages + shipped suggestions + an exact-identifier probe.
  - *Content* for uploaded installers is served over the gRPC channel (`FetchContent`), authorized per live job and hash (D42). Vendor installers are downloaded by the device directly (D16).
  - *Job types in use:* `SOFTWARE_INSTALL`, `SOFTWARE_UPDATE`, `SOFTWARE_UNINSTALL` and `INVENTORY_FULL`; the agent's local policy ceiling (`--allowed-jobs`) is enforced for them. States are `queued, sent, accepted, waiting, running, succeeded, succeeded_reboot, failed, expired, cancelled, rejected`.
  - *Delivery:* the server signs a job when it dispatches it (on creation to online devices, on connect for the rest), re-offers it with a fresh nonce until the agent's `JobUpdate` acknowledges it, and the agent persists jobs and results in its bbolt state with a durable outbox (D49). A cancelled job the agent may still hold is flagged `cancel_pending` and a `CancelBody` job is sent when the device is next reachable.
  - *Pipeline order on the agent:* preconditions (free space, OS build) → pre-detection (already installed = success, nothing run) → stage → download and SHA-256 → locked re-open and re-hash → Authenticode via `WinVerifyTrust` and signer pin → run in a Job Object → exit-code map → post-detection. Retryable codes (MSI 1618, another install in progress) back off inside the job's expiry.
  - *Scheduling:* `not_before`, a maintenance window in device-local time (or a fixed IANA zone), expiry, user-logon waiting (session-change events plus a 15-minute poll only while user jobs wait), cancellation. Idle sleep is bounded (default 5 min) so a wake source is never missed.
  - *Uninstall* is always derived on the device from that inventory row's own registry data (MSI product code → quiet string → uninstall string plus known Inno switches). HKLM executables must pass `TrustedExecutable` (under Program Files, Windows or the Package Cache); HKCU strings run only through the helper.
  - *Helper:* the service runs the pipeline; the helper only starts the verified command in the user's session (D45). The service passes it a JSON task over an anonymous pipe (inherited handle list; no named pipe). The helper re-verifies the signed envelope, device/org, that its own SID equals the target, that the staged file lies under its own staging directory, and the file's hash; the result is size-capped (64 KiB) and untrusted.
  - *Per-user policy* resolves package override → organization default (D47). Machine deployments that find per-user copies apply it: report only, update in place (skipped for self-managed apps, D50), convert to machine (uninstall is a dependent job, D48) or remove.
  - *Not built in Phase 3:* rings and success thresholds, reboot policy beyond "report", manifest dependency resolution, the peer-cache source, MSIX, the self-update loop guard, `requires_elevation` helpers, group-level policy.
- **Phase 4 as built (differences from §6 and §9, with decision numbers in DECISIONS.md):**
  - *Reporting* is a full-replacement `WU` section of the inventory report: the agent keeps a generation counter (`wu_gen`/`wu_sent`) and the server remembers the last generation it applied (`devices.wu_rev`, sent in Hello as `revs["wu"]`); a mismatch triggers `ResyncSections` (D58). Installed updates are never reported, only what is missing, downloaded, hidden, pending a restart or failed.
  - *Approvals* are per update identity, not per revision. Pending is the absence of a row. Rules only act on pending updates and never override a manual decision (D59).
  - *Rings* are ordered. A device belongs to the first ring whose groups contain it; devices in no ring are not touched automatically. Each ring has `delay_days` (after approval), `soak_hours` (before the next ring opens), a success threshold, an optional maintenance window and a restart policy (D60).
  - *Gating* (`gate()` in `internal/server/updates/schedule.go`): the next ring opens when the previous one has soaked and at least half of its devices have reported (or a week has passed since the soak). A failure rate above the allowed rate raises a hold at once; a released hold counts as a pass. A ring that has nothing to do for an update does not block the next one, a ring that has not started does (D60).
  - *Scheduler tick* (once a minute): at most 500 jobs per tick, at most 50 updates per job, jobs live 7 days, at most 3 automatic failures per (device, update) with at least 24 hours between tries (D61). Jobs are created (and dispatched ahead of time, so offline devices run them when they reconnect) for active devices in the ring that are missing an approved update.
  - *Source settings* (service and drivers) are an organization setting. Devices get them as a `WU_SCAN` job when their `wu_settings_rev` is behind; the agent stores the options and repeats the scan every 24 hours on its own (D62).
  - *Reboot:* an install job carries a `RebootPolicy`. The agent persists a reboot plan, re-evaluates it every tick, never starts a restart inside active hours (except "deadline" at the deadline), and starts it with `InitiateSystemShutdownEx` so signed-in users see a countdown and an administrator can abort with `shutdown /a`. Install jobs cannot ask for an immediate restart; the explicit `REBOOT` job needs an online device and a countdown of at least one minute (D63).
  - *Conflicts:* the agent reports WSUS (`UseWUServer`), Windows Update for Business deferrals, "configure automatic updates" and a disabled `wuauserv`; the console shows a banner on the device and a list under Update policy. LibrePatch never changes these policies (D64).
  - *Hiding* an update (manual "hide on devices") queues `WU_HIDE` jobs for devices that have it; hidden updates stay in the catalog with state `hidden`.
- **Phase 5 as built (differences from §10 and the Phase 5 plan, with decision numbers in DECISIONS.md):**
  - *Release trust* is a vendor Ed25519 key compiled into the agent; the signed manifest names the binary by SHA-256 (D68). `cmd/librepatch-release` creates keys and bundles; for a KMS/HSM it can emit the bytes to sign (`manifest`) and attach the signature (`attach`).
  - *Slots and rollback* (D69): `Program Files\LibrePatch\Agent\slot-a|slot-b`; the service image path is the switch. The old binary's `rollback-check`, run by a one-shot SYSTEM scheduled task at +10 minutes, restores the old slot unless `update.json` says `healthy`. A restart is a deliberate non-zero service exit, which needs the recovery option "also on non-crash failures" (set at install and re-asserted at every switch).
  - *Rollout* (D70): one target release per organization, optional pilot groups, soak hours, success threshold, a per-minute batch limit and a maintenance window. A failing pilot pauses the rollout and writes an audit entry. Up to three attempts per device and release, a day apart.
  - *Access model* (D71): a role binding is organization-wide or for one site. Site bindings grant only the permissions that act on a device from its own page (devices, deployments and updates on that device, catalog read); org configuration and fleet-wide views need an organization-wide role. Out-of-scope devices answer 404.
  - *API tokens* (D72) and *security keys* (D73): see SECURITY §9d.
  - *Software policies* (D75): the scheduler (every 5 minutes) turns a policy into an ordinary deployment for the devices that need it; nothing bypasses the deployment engine.
- **Linux agent build:** the agent core builds on Linux with a 0600 file key store and a `/sys`-based collector. This is used **only** for integration tests and the browser test, and is never shipped.


## 1. System overview

```
                    ┌───────────────────────── docker-compose host ──────────────────────────┐
 Admin browser      │                                                                        │
  ── HTTPS 443 ───▶ │  caddy ──http (internal net)──▶ librepatch-server ──(internal net)──▶ postgres │
                    │  (ACME / tls internal /           │  REST API + GUI + SSE                  (no published port)
                    │   admin cert)                     │  scheduler, catalog sync, CA, signer │
 Windows agents     │                                   │                                       │
  ── mTLS 1.3 8443 ─┼──────────── published directly ──▶│  agent gateway (gRPC, terminates mTLS)│
                    └───────────────────────────────────┼───────────────────────────────────────┘
                                                        │ HTTPS out: winget CDN (catalog),
                                                        │ vendor URLs (only if caching is enabled)
 Agent ── HTTPS out ──▶ vendor/winget installer URLs (SHA-256 verified), or the server content endpoint
```

Key choices:

- **One server binary, several roles.** The API, the gateway and background workers are packages inside one process. Splitting the gateway into its own container later is a deployment change, not a rewrite: it talks to the rest only through Postgres and the `hub` interface, which can be backed by LISTEN/NOTIFY.
- **The agent channel bypasses the reverse proxy.** The server terminates mTLS on 8443 itself and checks each client certificate against the database. No proxy decides who an agent is, and no certificate is passed in a header (see SECURITY.md T-NET-3).
- **Agents pin our internal root CA.** The agent channel needs no public certificate and no ACME. The ACME / `tls internal` / admin-cert choice affects only the browser-facing GUI.

## 2. Server internals

```
cmd/librepatch-server            subcommands: serve | migrate | backup | restore | ca | admin | healthcheck
internal/server/
  api/        chi router, handlers generated from api/openapi.yaml (oapi-codegen), request validation
  auth/       sessions, argon2id, TOTP, WebAuthn (Phase 5), CSRF, RBAC evaluator, API tokens, OIDC-ready identities
  gateway/    gRPC mTLS listener, per-device stream, cert→device binding, revocation check, rate limits
  hub/        registry of connected devices (device_id → stream), dispatch wake-ups (in-proc; LISTEN/NOTIFY later)
  enroll/     enrollment tokens, CSR validation, approval queue
  pki/        root / issuing-intermediate / job-signing certificates, issuance, renewal, revocation list
  signer/     job envelope signing (Ed25519); key held in memory, encrypted at rest with the server KEK
  inventory/  delta ingest, title normalization, version keys, device users
  catalog/    winget index sync + import, custom packages, overrides, detection rules, content store
  deploy/     deployments → rings → jobs; maintenance windows; approval rules; policies (auto-update, baselines)
  wu/         Windows Update catalog, approvals, device update state (Phase 4)
  sse/        per-session event broker (job status, device online/offline)
  audit/      append-only, hash-chained writer
  db/         sqlc-generated queries; migrations embedded (goose)
  reports/    CSV export (formula-injection-safe)
  license/    offline license verification (Phase 6)
```

**Concurrency model.** Each connected agent has a goroutine pair (receive and send). The dispatcher is woken by a "device online" event or a "job created for device X" event. It sends queued jobs to online devices and marks them `sent`. A device is `acked` once its agent has saved the job to disk. Nothing polls the database on a tight loop.

**Background workers** run in-process with a Postgres-backed lease, so two replicas can never run the same worker twice:

- catalog sync (every 6 hours);
- deployment ring promotion (every minute; cheap, indexed);
- job expiry;
- certificate-expiry and stale-device reports;
- audit-chain verification (daily).

## 3. Agent internals

```
cmd/librepatch-agent             subcommands: service (default) | helper | enroll | rollback-check | version
internal/agent/
  service/    SCM integration (x/sys/windows/svc), session-change notifications, shutdown handling
  identity/   CNG key (TPM "Microsoft Platform Crypto Provider", falling back to non-exportable software KSP), cert store, renewal
  conn/       gRPC client, keepalive, backoff+jitter reconnect, HelloAck clock offset
  store/      bbolt: config, job queue, result outbox, executed-job ledger, inventory snapshots + revision
  jobs/       envelope verification, local policy ceiling, scheduler (not_before, maintenance window, active hours), executor
              two loops (D116): one runs jobs one at a time, one runs restart requests and the restart countdown, so a
              restart never waits behind a scan or an inventory; it does wait for an installer or update it would interrupt
  inventory/  collectors (hardware, os, software/registry, msi, appx, portable, users), differ, change watchers
  engine/     installer engine: fetch → verify → stage → run (per-type arg builders) → detect → result
  userctx/    session resolution, token, environment, CreateProcessAsUser, anonymous-pipe IPC, helper side
  wua/        WUA COM (go-ole) on a dedicated locked OS thread (Phase 4)
  selfupdate/ A/B slots, verification, promotion, rollback (Phase 5)
  platform/   interfaces for every Windows call, so core logic is unit-tested on Linux with fakes
```

### 3.1 Performance budget and how we meet it

| Budget | Approach |
|---|---|
| Idle CPU about 0% | No polling loops. Wake-ups come from the gRPC stream, `RegNotifyChangeKeyValue`, `NotifyIpInterfaceChange`, session-change events and a few long timers (heartbeat every 5 min, reconcile daily). gRPC keepalive pings run every 90 s, which is enough to survive common NAT/firewall idle timeouts. |
| RSS under 30 MB | `GOMEMLIMIT=24MiB`, streaming hashing and diffing (inventory is never held as one big JSON), bbolt mmap kept small, WUA COM only loaded when scanning. Measured in CI on a Windows runner. |
| Binary about 15 MB | `-trimpath -ldflags="-s -w"`, no reflection-heavy dependencies, binary size checked against a budget in CI. |
| Never slow the machine down | Scans call `SetPriorityClass(PROCESS_MODE_BACKGROUND_BEGIN)` on the agent itself, which lowers CPU, I/O and memory priority. Hashing is rate-limited. Installers start at `BELOW_NORMAL_PRIORITY_CLASS` inside a Job Object. Work is postponed during Windows active hours unless the job's policy says otherwise. Battery and metered-network checks are available as preconditions. |

### 3.2 Files and ACLs on the endpoint

| Path | Owner / ACL (protected, no inheritance) | Contents |
|---|---|---|
| `C:\Program Files\LibrePatch\Agent\` | SYSTEM: Full; Administrators: Full; Users: Read+Execute | `slot-a\librepatch-agent.exe`, `slot-b\...` |
| `C:\ProgramData\LibrePatch\` | SYSTEM: Full; Administrators: Full (needed for support/uninstall) | `config.json`, `state.db`, `logs\` |
| `C:\ProgramData\LibrePatch\stage\machine\<job>\` | SYSTEM: Full only | machine-scope installers |
| `C:\ProgramData\LibrePatch\stage\user\<SID>\<job>\` | SYSTEM: Full; *target SID*: Read+Execute (**not** write) | user-scope installers |

The service `ImagePath` is quoted, and the service DACL denies non-admins `SERVICE_CHANGE_CONFIG`, `SERVICE_STOP` and similar rights. The agent calls `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` at start-up. Installers always run with the staging directory as their working directory. Because nobody but SYSTEM can write there, DLL planting next to the installer is not possible.

## 4. Inventory *(Phase 1: hardware; Phase 2: software, implemented)*

**Phase 2 as built, where it differs from the design below:**
- AppX is read from the registry (`...\Appx\AppxAllUserStore`, per-package and per-user subkeys), best effort and undocumented. `PackageManager.FindPackagesForUser` (WinRT) is deferred to Phase 3, which needs WinRT for MSIX installs anyway (D33).
- Portable packages are the winget `Packages` directories under each profile (`AppData\Local\Microsoft\WinGet\Packages`) and under `%ProgramFiles%\WinGet\Packages`; a directory is dropped when the same package has an Add/Remove Programs entry.
- MSI rows are emitted only for products with no Uninstall key (no double counting).
- `self_updating` hints belong to the catalog (Phase 3), not the inventory.
- The agent keeps a hash snapshot instead of a copy of the data (D31); the code is in `internal/agent/inventory` (`Scanner` over `Platform`/`RegNode` interfaces, so it is unit-tested on Linux with fakes; `*_windows.go` holds the Win32 code; `Manager` runs the protocol; `Watcher` waits on `RegNotifyChangeKeyValue` handles).
- Scans run on a low-priority thread (`THREAD_MODE_BACKGROUND_BEGIN`) and a change that arrives while a report is still unacknowledged is marked dirty and rescanned right after the acknowledgement.


**Sources:**

- **Machine scope:**
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`, 64-bit and 32-bit (`WOW6432Node`);
  - MSI products (`MsiEnumProductsEx` for all contexts);
  - provisioned AppX;
  - portable packages under our own `C:\Program Files\LibrePatch\Portable`.
- **User scope, for each profile under `HKLM\...\ProfileList`:**
  - if the profile is loaded, read `HKU\<SID>\...\Uninstall`;
  - otherwise copy its `NTUSER.DAT` (plus `.LOG1`/`.LOG2`) to a temporary directory under the protected data directory and load the **copy** privately with `RegLoadAppKey`, deleting it afterwards (a direct load can rewrite the user's hive; see research U8 and D40);
  - `%LOCALAPPDATA%\Microsoft\WinGet\Packages` (winget portable);
  - per-user AppX via `PackageManager.FindPackagesForUser`.
- **Hardware/OS:**
  - native APIs where they're cheap: OS build and UBR, CPU, RAM, IPs, uptime;
  - WMI only on scan: serial (`Win32_BIOS`), chassis, disks, BitLocker (`Win32_EncryptableVolume`);
  - pending-reboot registry markers (CBS, WU, PendingFileRenameOperations, computer rename);
  - last logged-on user and active sessions.

**Each software row** carries: `scope` (machine/user), `user_sid`, `source` (`reg64`/`reg32`/`hku`/`msi`/`appx`/`portable`), a stable `key` (Uninstall subkey name / ProductCode / PackageFullName / portable ID), name, version, publisher, install date, location, uninstall and quiet-uninstall strings, product code, a `system_component` flag, and a `self_updating` hint.

**Change detection:**

1. A change watcher fires.
2. The agent debounces for 30 s.
3. It rescans only the affected section.
4. It diffs against the stored snapshot.
5. It sends a delta with `base_rev → new_rev`.

The full protocol is in PROTOCOL.md §6. A full reconcile runs daily at background priority, and on demand.

## 5. Job model

The agent executes only these **typed** jobs: `INVENTORY_FULL`, `SOFTWARE_INSTALL`, `SOFTWARE_UNINSTALL`, `SOFTWARE_UPDATE`, `WU_SCAN`, `WU_INSTALL`, `WU_HIDE`, `REBOOT` and `AGENT_UPDATE`. There is no "run command" job type in v1.

**Agent-side lifecycle:**

```
received → verified → persisted+acked
  → waiting(not_before | maintenance window | active hours | user logon)
  → preconditions → running → detecting → result queued → result delivered
```

**On a verification failure**, the job is rejected, the rejection is reported (signed-job failures are a security event), and nothing executes.

**Agent and server keep job state separately.** The server's job states mirror the agent's: queued, sent, acked, waiting_window, waiting_user_logon, running, succeeded, succeeded_reboot_required, failed, expired, cancelled.

**Retries:**

- *Retryable* exit codes (e.g. MSI 1618 "another install in progress") are retried by the agent with backoff, within the job's expiry.
- *Terminal* failures are reported. The server may issue a new attempt, which is a new job ID.

## 6. Deployment engine *(Phase 3/4/5)*

A **deployment** has these parts:

- **What:** packages and versions, an action, or a set of Windows updates.
- **To whom:** groups (static or dynamic) and devices, resolved per ring.
- **When:** start time, maintenance window, deadline.
- **Reboot policy.**
- **Rings:** for example pilot (group A) for 2 days with ≥95% success, then broad.

The ring promoter moves to the next ring once the time has passed and the success threshold is met. If the threshold isn't met, the deployment pauses and alerts the admin.

**Signing timing.** Jobs are created per device as rows, and the envelope is signed when the job is dispatched. Jobs are dispatched **ahead of time**, carrying `not_before` and the maintenance window, so an agent can run them without contacting the server, as the brief requires. `expires_at` bounds how long a job is valid.

**Maintenance windows** are evaluated **on the device**, in device-local time by default or in a fixed time zone. The window definition (days of week, start time, duration) is in the signed payload.

**Windows-update approval rules** (Phase 4, as built): (classification, severity, include drivers) → auto-approve once the update is N days past its release date. Rings add their own delay after approval. Manual approve, decline and hide decisions always win over rules and are audited. Product filters were not built.

**Policies** (Phase 5):

- *auto-update:* keep package set P at the latest approved version on group G, with a delay of D days and rings;
- *baseline:* install P on newly enrolled devices in group G;
- *per-user app policy* (§7.4).

## 7. Install engine *(Phase 3)*

### 7.1 Catalog: winget as metadata only
1. **Sync.** The server downloads the winget pre-indexed source from the winget CDN, verifies its MSIX signature against Microsoft's code-signing chain, and stores a searchable index of IDs, names, publishers and versions. Full manifests are only stored for packages an admin **imports**.
2. **Import.** The server fetches the manifests for the selected package and versions and normalizes them. For each installer it stores: URL, SHA-256, type, nested type, architecture, scope, switches, success and expected codes, product and upgrade codes, dependencies and minimum OS. It also generates default **detection rules** from `AppsAndFeaturesEntries`/`ProductCode`.
3. **Verified flag.** Our own tested list ships as a signed catalog overlay. It contains corrected switches, detection rules and a `self_updating` mark. Unverified packages carry a warning in the GUI, and deploying one needs the "operator+" role plus a confirmation step that is audited.
4. **Admin overrides,** per organization: silent args (validated tokens only, §7.3), extra detection rules, version pin (`= x`, `< x`, `latest`), exclusions, and per-user app policy.
5. **Custom packages.** The admin uploads an installer. It's stored content-addressed by SHA-256, and the admin defines the type, args, detection, uninstall and scope.
6. **Licensing default.** The agent downloads **directly from the vendor/winget URL** and verifies the hash. The server never mirrors third-party installers unless an admin enables "cache content", which shows a notice that redistribution rights are the admin's responsibility (this is not legal advice). Custom uploads are, by definition, the admin's own content.

### 7.2 Content delivery (bandwidth)

The agent tries an ordered list of `ContentSource`s, and **every source is untrusted**. The bytes must match the SHA-256 in the signed job no matter where they came from. That's what makes adding peer-to-peer later safe.

1. *Peer cache* (D126): other agents on the same network that have the file, offered by the server as `PEER` sources in the signed job; off unless the organization turns it on.
2. Server content endpoint (`/v1/content/{sha256}`, over mTLS, supports ranges and resume), used when cached or custom.
3. Vendor URL from the manifest (HTTPS, system trust store, with a size limit taken from the catalog).

### 7.3 Execution

1. **Fetch** to `stage\machine\<job>` or `stage\user\<SID>\<job>`. This is SYSTEM-only, or SYSTEM-write plus user read/execute. Hashing happens while streaming.
2. **Verify:**
   - **Reopen** the file with `FILE_SHARE_READ` only, so nobody can write or delete it, and re-hash it from that handle.
   - Verify Authenticode (`WinVerifyTrust`). If the catalog has a pinned signer, check the signer matches. A signer change on an otherwise valid hash is an **alert**, and policy can also make it a block.
   - **Keep the handle open** until the process has started, which closes the TOCTOU window.
3. **Build the command line** from an argument *array*. Rules:
   - Never call `cmd.exe` or PowerShell.
   - Quote with `windows.ComposeCommandLine`.
   - Per-type builders:
     - MSI: `msiexec.exe /i <path> /qn /norestart /l*v <log>`, plus `ALLUSERS=1`, or `ALLUSERS=2 MSIINSTALLPERUSER=1` for user scope;
     - MSIX: `PackageManager` API, not a process;
     - Inno: `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /ALLUSERS|/CURRENTUSER`;
     - NSIS: `/S`;
     - Burn: `/quiet /norestart`;
     - `exe`: manifest or override switches only;
     - `portable`: copy and register;
     - `zip`: extract with zip-slip protection, then use the nested installer.
   - Admin-supplied extra args are parsed into tokens and checked against an allow-pattern, e.g. `PROPERTY=value` with a safe character set, or known `/switch` forms.
4. **Run** inside a **Job Object**, which:
   - tracks the whole process tree (many EXE installers re-spawn themselves and exit early; we wait for the tree, not the first PID);
   - enforces the timeout (default 60 min) by killing the tree;
   - applies the below-normal priority class.
5. **Map the exit code:** manifest codes, then type defaults (MSI 0/1641/3010/1618), then overrides. The result is success, reboot required, retryable or failed.
6. **Detect** with the scope's rules (§7.6). A success exit code with a failed detection is reported as `failed_detection`, not success.
7. **Clean up** staging and attach the tail of the installer log (size-capped) to the result.

### 7.4 Scopes and per-user app policy

**Who runs the job** depends on the scope of the target package or installed row:

- **Machine:** the SYSTEM service runs the engine directly.
- **User:** the service resolves the target SID to an active session and launches the helper (§8). The helper runs the same engine code with the user's token. If no session exists, the job enters `waiting_user_logon`, with an expiry. The GUI shows "waiting for user logon".

**Per-user app policy** has four settings. It is resolved per app, then per group, then globally; the most specific wins, and the resolved value is shown in the GUI with where it came from.

| Policy | Behaviour |
|---|---|
| `report_only` (default) | Inventoried and shown; never touched. |
| `update_in_place` | A user-scope update job through the helper. |
| `convert_to_machine` | Two linked jobs: (a) machine install of the same package. Only if (a) succeeds and detection passes: (b) user-scope uninstall through the helper, run at that user's next session if needed. Only offered when the catalog has a machine-scope installer. The GUI warns that user settings may need redoing. |
| `remove` | A user-scope uninstall through the helper. |

### 7.5 Uninstall
Preferred order:

1. MSI product code: `msiexec /x {GUID}`, GUID validated by regex.
2. Catalog-defined uninstall.
3. Recorded `QuietUninstallString`.
4. `UninstallString` plus known silent switches for the detected installer type.

**HKCU uninstall strings are user-controlled data.** They are only ever run in that user's context, through the helper, and **never as SYSTEM**. HKLM strings run as SYSTEM only after parsing:

- the executable path must be absolute and exist;
- it must not be in a user-writable location (checked against the effective DACL of the file and its parent directories);
- the arguments are re-tokenized, never passed through a shell.

### 7.6 Detection
- Rule types: MSI product code (+ version comparison), registry value (key/value/version comparison, with hive chosen by scope), file version (path with only allow-listed environment variables), AppX package family (+ version).
- Machine rules evaluate HKLM and machine paths only. User rules evaluate *that user's* hive and profile paths, with the helper reporting results for logged-on users or the service reading the offline hive.
- Inventory and job results always carry scope and SID. "Installed / not installed" is always a statement about a specific (scope, SID).
- Version comparison uses one shared Go implementation, ported from winget's semantics, so server and agent agree.

### 7.7 Self-updating apps
- The catalog overlay marks Chrome, Edge, Teams (new), Zoom, Firefox, Slack and others as `self_updating`, with an optional "vendor updater healthy" detector (e.g. the Google Update service or scheduled task is present).
- The policy is either `defer_to_vendor` (default: report staleness only after N days behind) or `enforce` (we deploy updates).
- **Loop guard.** If our install is followed by a vendor update within X hours, or a version flip-flop is seen twice, auto-update for that app on that device is suspended and an alert is raised.

### 7.8 Dependencies, pinning, exclusions
- Manifest `PackageDependencies` are resolved on the server into ordered sub-jobs, all in the same envelope.
- Pins and exclusions are enforced on the server when jobs are created. The agent also refuses a job that would downgrade unless `allow_downgrade` is set in the signed payload.

### 7.9 VM test matrix (run before an app is marked supported)

**Environments:** Windows 10 22H2, Windows 11 24H2 and Server 2022, each with:

- an admin user;
- a standard user;
- two users at once (fast user switching);
- an RDP session;
- the target user logged off.

**Scenarios:** machine-only install, user-only install, both installed for the same app, update in place, convert to machine, remove, uninstall, offline-profile inventory.

**Packages:** VS Code (user and system installers), Zoom, Google Chrome, Microsoft Teams, Postman, Discord, 7-Zip, Notepad++, Firefox, plus one plain MSI and one MSIX.

Our harness runs the matrix as a scripted checklist through the real agent and server, and stores per-run results in `test/vm-matrix/results/`. The GUI shows an app as "supported (user/machine scope)" only if it has a passing result for that scope.

## 8. User-context helper *(Phase 3)*

```
SYSTEM service                                              user session (SID S, session N)
 1. job verified; target SID S; scope=user
 2. resolve S → session N (WTSEnumerateSessions; prefer active console, then active RDP)
 3. token = WTSQueryUserToken(N)  (filtered token; never TokenLinkedToken unless job.requires_elevation*)
 4. CreatePipe() → (svcEnd, helperEnd); helperEnd inheritable
 5. CreateEnvironmentBlock, LoadUserProfile
 6. CreateProcessAsUser(token, "<slot>\librepatch-agent.exe helper", STARTUPINFOEX{HANDLE_LIST=[helperEnd]},
    CREATE_SUSPENDED | CREATE_NO_WINDOW | BELOW_NORMAL, lpDesktop="winsta0\\default")
 7. assign to Job Object (timeout, kill-on-close), ResumeThread  ───────────────▶ helper starts
 8. send HelperTask{job envelope, staged path, sha256, deadline} over pipe ─────▶ re-verifies envelope signature,
                                                                                  device id, SID == own token SID,
                                                                                  expiry; re-hashes file; runs engine
 9. read HelperResult (size-capped, schema-validated, treated as untrusted) ◀──── result, detection, log tail
10. helper exits; the service applies a server-side sanity check (e.g. detection via HKU\S) before reporting
```

- **No listening endpoint.** The pipe is anonymous and its handle is passed only to the child. The helper takes exactly one task and exits.
- **No elevation.** \*`requires_elevation` is reserved and not implemented in v1. Per-user installers that need elevation are marked unsupported for user scope.
- **The helper re-verifies everything.** It is the same binary with the same pinned keys. A user-level process that tampered with the helper could only make it lie about results for that same user. The service double-checks detection where it can.
- **Session notifier** (Phase 4) uses the same mechanism to show reboot or deadline notices. It shows text and returns a button choice, and runs no code.

**Logon-triggered queue:**

- *Primary:* `SERVICE_CONTROL_SESSIONCHANGE` (logon, unlock, remote connect) → check the queue for that SID.
- *Fallback:* only while user-scope jobs are pending, a reconcile runs every 15 min with `WTSEnumerateSessions`. There is also a SYSTEM-principal "at logon of any user" scheduled task that signals the service through a named event whose DACL allows only SYSTEM.

## 9. Windows Update *(Phase 4)*
- WUA COM via go-ole, on one goroutine pinned to an OS thread, with `CoInitializeEx(MTA)`.
- The service source is configurable per policy: Windows Update, Microsoft Update (Office etc., service ID `7971f918-a847-4430-9279-4a52d1efe18d`), or the machine's default/managed WSUS.
- Scan queries: `IsInstalled=0 and IsHidden=0` plus `Type='Driver'` for drivers.
- Results are reported as (UpdateID, RevisionNumber, KB, classification, severity, driver fields).
- Install runs only for the UpdateID/revision pairs listed in the signed job. Hide and unhide use `IUpdate.IsHidden`.
- Conflict detection reports WSUS (`UseWUServer`), WUfB deferral policies and "configure automatic updates" GPO, so admins know who is in charge.
- Reboot handling: we check `RebootRequired` and the pending markers, then apply the reboot policy. The policy respects active hours and the maintenance window; the countdown is the system's own shutdown notice (D63) rather than a custom session notifier.
- *As built:* see §0 "Phase 4 as built". The COM implementation is `internal/agent/wu/wua_windows.go`; non-Windows builds use a scripted dev client (`wu-dev.json` in the data directory) for tests and demos.

## 10. Agent self-update *(Phase 5, as built)*
1. The server offers `AGENT_UPDATE` (a job signed like every other) carrying a **release manifest signed by the vendor release key**. That key is compiled into the agent and is separate from every customer server key. A compromised customer server can't push a custom agent (PROTOCOL §5.2c).
2. The agent verifies the manifest, downloads the binary over the mTLS channel, checks SHA-256 and size twice, checks the Authenticode subject the manifest pins, and runs the binary with `version` to see it is the promised release.
3. It copies the binary into the inactive slot, writes `update.json` (`switching`, deadline +10 min) and arms a one-shot SYSTEM task, `\LibrePatch\rollback-check`, that runs the *current* slot's binary at the deadline. If the task cannot be armed, nothing is switched.
4. It points the service `ImagePath` at the new slot and exits non-zero; the service manager restarts it (recovery action) on the new binary.
5. When the new version completes its first handshake with the server it writes `healthy`, deletes the task and the update job succeeds.
6. If it never does (crash loop, cannot reach the server), the task restores `ImagePath`, restarts the service on the old version, writes `rolled_back`; the old agent then reports the job as failed.

Everything except the Windows-specific calls (`mgr`, `schtasks`, the restart) is exercised on Linux by a development platform that implements the same interface with files (`TestAgentSelfUpdateEndToEnd`, `internal/agent/jobs/selfupdate_test.go`). A broken release (`test/tools/brokenagent`) is the Windows test for step 6.

## 11. Repository layout

```
/
├── cmd/
│   ├── librepatch-server/        server main
│   ├── librepatch-agent/         agent main (windows; core builds on linux for tests)
│   ├── librepatch-release/       vendor tool: agent release keys and signed bundles
│   └── librepatch-loadsim/       simulated agents for integration and load tests
├── internal/
│   ├── server/...             see §2
│   ├── agent/...              see §3
│   └── shared/                protocol helpers, envelope sign/verify, version compare, detection-rule types
├── proto/librepatch/agent/v1/    .proto files (buf lint + breaking-change check in CI)
├── gen/                       generated code (protobuf, sqlc) — committed, CI verifies it is up to date
├── api/openapi.yaml           REST contract
├── db/migrations/             goose SQL migrations
├── db/queries/                sqlc queries
├── web/                       React + TS + Vite app (built into internal/server/webui via go:embed)
├── deploy/
│   ├── docker-compose.yml     production compose (caddy, server, postgres)
│   ├── compose.dev.yml        dev overrides
│   ├── caddy/                 web proxy image (both Caddyfiles built in)
│   ├── postgres/              database image (role setup + first-start password wrapper)
│   └── Dockerfile.server      multi-stage → distroless/static:nonroot
├── installer/wix/             agent MSI (Phase 5)
├── catalog-overlay/           verified-package overlay (signed at release)
├── test/
│   ├── e2e/                   in-process server + agent core against real Postgres (also runs on Windows with real CNG keys)
│   ├── integration/           docker-compose stack + real agent process (`-tags compose`)
│   ├── tools/bootstrap/       drives first-run setup and token creation (CI, demos)
│   └── vm-matrix/             Windows VM matrix harness + results (Phase 3)
├── scripts/                   dev and release helpers
├── docs/
└── .github/workflows/         ci.yml, windows.yml, release.yml (CodeQL runs as GitHub's default setup, not a workflow file) / semgrep
```

One Go module keeps protocol and shared code in lockstep. Platform-specific agent code uses `_windows.go` files behind the `platform` interfaces.

## 12. Testing strategy
- **Unit:** all core logic (envelope verification, schedulers, differs, arg builders, exit-code maps, filter-to-SQL compiler, RBAC) runs on Linux with fakes.
- **Database:** sqlc queries are tested against a real Postgres (testcontainers in CI).
- **Integration (Linux CI):** `docker compose` brings up the server and Postgres. The real agent core binary (Linux build, fake Windows collectors) enrolls, connects, receives signed jobs and reports results. Tamper tests flip bytes in envelopes, replay jobs, send them to the wrong device, and revoke mid-stream.
- **Windows CI:** the GitHub `windows-latest` runner (it has PostgreSQL preinstalled) runs the server natively and the real agent service. It checks enrollment, inventory, an MSI install/uninstall of a test package, and binary-size and RSS budgets.
- **Fuzzing:** Go native fuzzing for protobuf handlers, manifest parsing, uninstall-string parsing, filter AST and zip extraction.
- **Load (Phase 6):** `librepatch-loadsim` runs 10k simulated agents doing enrollment, steady state, inventory deltas, deployment fan-out and a reconnect storm.
- **VM matrix:** §7.9.
