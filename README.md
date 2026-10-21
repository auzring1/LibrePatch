# LibrePatch

Free, self-hosted patch and software management for Windows endpoints. A small Go agent runs on each PC, a Go server with a
REST API and web console runs in Docker on your own hardware, and nothing leaves your network: there is no cloud service,
no account and no telemetry.

**What it does**
- **Inventory:** every installed program (machine-wide and per user), hardware, users and groups, with search and CSV export.
- **Software updates and deployment:** finds updates for installed programs by matching them to the winget community index, with
  no catalog to maintain; installs and updates from winget manifests or your own uploaded installers, with hash checks,
  maintenance windows and a verified/unverified safety step. Software policies can roll a new version out ring by ring and wait for your approval first, and signed overlays record the silent arguments and verified marks you have tested.
- **Vulnerabilities:** matches the public CISA exploited-vulnerability list and the NIST database against Windows and the programs on your devices, entirely on your server (off until you turn it on).
- **Windows Updates:** approval, update rings, maintenance windows, reboot policy and compliance reports.
- **Alerts and lifecycle:** e-mail or webhook alerts for offline PCs, failed installs, restarts that wait too long, low disk space, BitLocker off and operating systems nearing end of support, plus a report of devices that are out of support.
- **Agent self-update** with a pilot group and automatic rollback.
- **Security first:** mutual TLS, jobs signed by the server and verified on the PC, mandatory two-factor sign-in with
  security-key support, role-based access (optionally per site), scoped API tokens and a hash-chained audit log.
- **Agents without GitHub:** the server hands out the Windows agent (MSI and exe) itself, and the console prints the install commands for both.
- **Your branding**, five accessible themes, encrypted backups, and an MSI for deployment through GPO, Intune or an RMM.

**Status: early software.** It comes with a large automated test suite (unit, database, end-to-end and browser tests), but it has
not had an independent security audit, and several Windows-only paths (the MSI, agent self-update, restart
handling) have had little real-world testing. It runs installers as SYSTEM on your computers, so treat it like any
new tool with that power: read [docs/SECURITY.md](docs/SECURITY.md), pilot on a few machines first, and keep backups.

## Quick start (production-style, one host)
The simplest install is **one file**: download `docker-compose.yml` from the latest
[release](https://github.com/auzring1/LibrePatch/releases), set your host name in the block at its top, and start it
(`docker compose up -d`, or paste it into a new project in Synology Container Manager). Everything else is inside the container
images. Details: [docs/RUNBOOK.md](docs/RUNBOOK.md), section 2.2. To build from a checkout instead:
```bash
cp deploy/.env.example deploy/.env              # set LIBREPATCH_HOSTNAME (and LIBREPATCH_CADDY_TLS)
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
docker compose -f deploy/docker-compose.yml logs server | grep -A2 "setup token"
```
Passwords and the encryption key are created for you on the first start. Open `https://<LIBREPATCH_HOSTNAME>`, follow the
setup wizard, and when you first sign in the console shows the **master key**: save it somewhere other than the server. Build the Windows agent with
`GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o librepatch-agent.exe ./cmd/librepatch-agent`
and install it on an endpoint with the command the console shows under **Enrollment**.

- Full operations guide: [docs/RUNBOOK.md](docs/RUNBOOK.md)
- Every setting, its default, limits and who may change it: [docs/SETTINGS.md](docs/SETTINGS.md) (generated from the settings registry)
- Fresh install on Windows 11 with Docker, from wiping the old setup to the first enrolled agent: [docs/FRESH-INSTALL-WINDOWS.md](docs/FRESH-INSTALL-WINDOWS.md)
- Step-by-step demos on a test VM: [Phase 1](docs/demos/PHASE1-DEMO.md), [Phase 2 (inventory)](docs/demos/PHASE2-DEMO.md), [Phase 3 (software deployment)](docs/demos/PHASE3-DEMO.md), [Phase 4 (Windows updates)](docs/demos/PHASE4-DEMO.md), [Phase 5 (self-update, access, policies, backup, MSI)](docs/demos/PHASE5-DEMO.md), [Phase 6 (hardening, load test, release dry run)](docs/demos/PHASE6-DEMO.md)

## Development
Requirements: Go 1.27 (the toolchain is pinned in `go.mod`), Node 22, Docker.
```bash
make tools                 # pinned generators and linters
make dev-db                # throwaway Postgres; prints LIBREPATCH_TEST_PG_URL to export
make web build             # console bundle, server, agent (windows + linux test build)
make test                  # unit, database and in-process end-to-end tests (race detector)
make test-gui              # Playwright: setup → MFA login → enroll a real agent → deploy a package → revoke, CSP-strict
make fuzz                  # 20 s per fuzz target over the untrusted-input parsers
make test-compose          # full docker-compose stack + real agent process
make lint vuln licenses    # vet, staticcheck, gosec, semgrep; govulncheck, npm audit; license allow-list
```
Run the web console against a local server: start the server with `LIBREPATCH_DEV_MODE=true LIBREPATCH_PUBLIC_URL=http://localhost:5173 ...`, then run `cd web && npm run dev`.

## Repository layout
| Path | |
|---|---|
| `cmd/librepatch-server`, `cmd/librepatch-agent`, `cmd/librepatch-release` | Binaries (`librepatch-release` is the release-signing tool: it signs the agent releases the server hands out) |
| `cmd/librepatch-loadsim` | Load generator that simulates thousands of agents against a server (see [docs/LOADTEST.md](docs/LOADTEST.md)); a test tool, not shipped |
| `internal/server/*` | API, auth/MFA, gateway, PKI, audit, store, web UI embedding |
| `internal/agent/*` | Agent core, CNG key store, hardware collector, Windows service, installer |
| `internal/shared/*` | Protocol helpers shared by both: envelopes, enrollment bundle, PKIX conventions |
| `proto/`, `api/openapi.yaml`, `db/` | Agent protocol, REST contract, migrations and queries |
| `gen/` | Generated code (protobuf, sqlc). CI checks it is up to date |
| `web/` | React + TypeScript + Mantine console (embedded into the server binary) |
| `installer/windows` | WiX sources and build scripts for the agent MSI |
| `deploy/` | Dockerfile, compose stack, and the small web proxy (`caddy/`) and database (`postgres/`) images |
| `test/` | End-to-end, compose integration, VM matrix harness (`test/vm-matrix`), CI tools |
| `docs/` | Plan, architecture, protocol, data model, security, decisions, runbook, demos |

## Documentation
| Doc | |
|---|---|
| [PLAN](docs/PLAN.md) | Summary, stack, roadmap |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Components, agent internals, install engine, user-context helper |
| [PROTOCOL](docs/PROTOCOL.md) | Enrollment, mTLS channel, signed jobs, inventory |
| [DATA_MODEL](docs/DATA_MODEL.md) | PostgreSQL schema |
| [SECURITY](docs/SECURITY.md) | Threat model, Phase 1 controls with evidence, known gaps, disclosure policy |
| [DECISIONS](docs/DECISIONS.md) | Owner decisions and engineering defaults |
| [RUNBOOK](docs/RUNBOOK.md) | Install, operate, troubleshoot (branding: §5g) |
| [Research: winget & user context](docs/research/winget-and-user-context.md) | Why we don't execute through winget |

**Console design:** semantic design tokens, five WCAG AA themes (Light, Slate, Dark, Midnight, High contrast) plus "follow my device", per-account preferences; see [docs/ui](docs/ui/README.md) for before/after screenshots.

**Branding:** the organization name, product name, logos, colors and sign-in texts are configuration, not source: set them in the first-run wizard and under Settings > Branding (administrators only).

## Contributing, security and license
- **Contributing:** bug reports, ideas and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
- **Security problems:** please report them privately; see [SECURITY.md](SECURITY.md).
- **License:** Copyright © 2026 the LibrePatch contributors. LibrePatch is free software under the
  [GNU Affero General Public License v3.0 or later](LICENSE). You may use it, including at work, and change it. If you run a
  modified version for other people, or distribute a modified agent, you must make your changes available under the same
  license. The name "LibrePatch" is not part of that license: see [TRADEMARKS.md](TRADEMARKS.md).
- Third-party components and their licenses: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
