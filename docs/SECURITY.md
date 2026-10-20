# Security and Threat Model

Status: threat model updated after Phase 1. It's updated every phase, and the Phase 6 security review is run against it. Every control lists the phase that delivers it. §9 lists what Phase 1 actually implements, with the test that proves each item.

## 1. Security goals
1. **Only the legitimate server, acting on an authenticated and authorized admin's intent, can make an endpoint execute anything**, and only from the fixed set of typed jobs.
2. **The network is hostile.** A machine-in-the-middle, a malicious proxy or a DNS hijack can't inject, alter, replay or redirect jobs.
3. **One compromised endpoint can't affect other endpoints or the server**, beyond its own inventory data and results.
4. **A local standard user can't use the agent to escalate privileges.**
5. **Only verified binaries get installed.** Every installer and every agent update is hash-verified, and signature-verified where possible, before it runs.
6. **Everything an admin does is attributable,** in an audit log that can be appended to but not edited.
7. **Server compromise is treated as catastrophic.** We reduce its likelihood and its blast radius, and we're honest about what we can't prevent (§6).

## 2. Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Job-signing private key | With it plus network position or server access, an attacker can run allowed job types as SYSTEM fleet-wide |
| A2 | Root CA key | Can mint job-signing certs and issuing CAs, so it's the top of trust |
| A3 | Issuing CA key | Can mint device certificates and gateway certificates (impersonate the server to agents for TLS, but **not** sign jobs) |
| A4 | Admin credentials, sessions, API tokens | Admin intent equals fleet control |
| A5 | Device private keys | Impersonate a device: feed false inventory, receive its jobs |
| A6 | Installer and agent binaries in transit and staging | Tampering means code runs as SYSTEM |
| A7 | Database | Inventory (usernames, hostnames, software = recon gold), audit log, encrypted keys |
| A8 | Server KEK (master key, a file on a Docker volume the server reads but cannot write) | Decrypts A1, A3 and the TOTP secrets at rest |
| A9 | Vendor release-signing key (ours, not the customer's) | Authorizes agent self-updates for *every customer* |
| A10 | Backups | Contain A7 and the encrypted key material |

## 3. Adversaries
- **External network attacker:** can reach the GUI and gateway ports, and may hold a network MITM position.
- **Malicious or compromised endpoint:** has SYSTEM on one enrolled device, so it holds that device's identity.
- **Local standard user** on a managed endpoint, possibly running malware.
- **Malicious or compromised upstream:** a poisoned winget manifest, a compromised vendor download, or a compromised dependency.
- **Insider:** a rogue operator, or a stolen admin session.
- **Attacker with access to the server host or containers.**

## 4. Trust boundaries

```
[Browser] ──TB1── [Caddy] ──TB2── [Server API] ──TB4── [Postgres]
                                   [Server gateway] ──TB3── [Agent service (SYSTEM)] ──TB5── [User helper (user)]
[Server] ──TB6── [winget CDN / vendor URLs]           [Agent] ──TB6── [vendor URLs]
[Agent service] ──TB7── [Local users / other processes on the endpoint]
[Vendor build pipeline] ──TB8── [Released agent / server artifacts]
```

## 5. Threats and mitigations

Statuses: ✅ designed in, 🔜 later phase (number given), ⚠ residual risk.

### TB3: Network between agents and server
| ID | Threat | Mitigation | Phase |
|---|---|---|---|
| T-NET-1 | MITM injects or alters jobs | TLS 1.3 + mTLS with the **root pinned by the agent**. Separately, every job is an **Ed25519-signed envelope**, verified before parsing and bound to device, org, expiry and nonce. A MITM with a valid TLS certificate still can't forge a job. | 1, 3 ✅ |
| T-NET-2 | Replay of a captured job, to the same or another device | `device_id` binding; `expires_at` (≤ 30 days); job-ID ledger kept past expiry; nonce | 3 ✅ |
| T-NET-3 | A proxy or header-forwarding setup tricks the server into trusting a spoofed client certificate | The gateway terminates TLS itself. No proxy is in the agent path, and we never read client identity from headers. | 1 ✅ |
| T-NET-4 | Rogue server (DNS hijack) | Agent pins the root SPKI. The enrollment bundle carries the pin, so trust on first use doesn't depend on DNS. | 1 ✅ |
| T-NET-5 | TLS downgrade | TLS 1.3 only, on both sides | 1 ✅ |
| T-NET-6 | Traffic analysis of inventory | All traffic is TLS. Metadata leakage (timing, size) is accepted. | ⚠ |

### TB3: Compromised endpoint against the server
| ID | Threat | Mitigation | Phase |
|---|---|---|---|
| T-DEV-1 | Device impersonates another device | Device ID taken from the verified certificate; never trusted from message fields | 1 ✅ |
| T-DEV-2 | Malicious inventory (XSS, CSV injection, SQL-looking strings, huge payloads) | Everything from agents is untrusted input: size limits, parameterized SQL, React escaping plus strict CSP, CSV formula escaping (`= + - @ \t \r` get a `'` prefix), schema validation; file paths an agent lists as queued for deletion are capped (16 per report, 1,024 characters each) and shown as plain text (D119) | 1–2 ✅ |
| T-DEV-3 | Resource exhaustion (flooding messages, inventory churn) | Per-device token-bucket rate limits, message size caps, max rows, connection limit per device certificate (1) | 1–2 ✅ |
| T-DEV-4 | Content scraping (download other tenants' or other devices' uploads) | Content served only if referenced by an active job for that device | 3 ✅ |
| T-DEV-5 | Stolen device key reused elsewhere | Key held in TPM/non-exportable CNG; one stream per certificate; admin revocation is immediate; a new connection from the same certificate supersedes the old stream and logs a warning (no alert) | 1 ✅ |
| T-DEV-6 | Falsified job results (claims patched when not) | Accepted risk for a compromised device, since we can't attest. Inventory cross-checks are shown. | ⚠ |

### Enrollment
| ID | Threat | Mitigation | Phase |
|---|---|---|---|
| T-ENR-1 | Token theft or mass rogue enrollment | Limited-use, expiring tokens stored hashed; optional admin approval; rate limits per IP and per token; enrollment events are audit entries (no alerts); tokens can be revoked | 1 ✅ |
| T-ENR-2 | Taking over an existing device's identity by re-enrolling | A matching hardware ID forces approval; the old certificates are revoked when the new one is approved | 1 ✅ |
| T-ENR-3 | Brute-forcing tokens | 256-bit tokens; generic errors; rate limits | 1 ✅ |

### TB7/TB5: Endpoint-local privilege escalation
| ID | Threat | Mitigation | Phase |
|---|---|---|---|
| T-LPE-1 | User swaps the installer between verification and execution (TOCTOU) | Staging is SYSTEM-write-only (user scope: SYSTEM-write, user read/execute). The file is opened deny-write, re-hashed from the handle, and the handle stays open through `CreateProcess`. | 3 ✅ |
| T-LPE-2 | DLL planting next to an installer running as SYSTEM | Staging directory can't be written by users. Working directory is staging. The agent itself uses `SetDefaultDllDirectories`. | 3 ✅ |
| T-LPE-3 | **User-writable `HKCU` uninstall strings run as SYSTEM** | Never. HKCU entries only run through the user's own helper. HKLM strings are parsed and the executable must lie under Program Files, the Windows directory or `ProgramData\Package Cache` (not a symbolic link). No shell is involved. **Not implemented: a DACL check on the file and its parents** (an app installed with a user-writable folder under Program Files, or anything under `Package Cache`, which is user-creatable). See 9f, R-1. | 3 ✅ / ⚠ |
| T-LPE-4 | Command-line injection through package metadata or admin args | Argument arrays, `ComposeCommandLine` quoting, no `cmd.exe`/PowerShell, allow-listed argument token patterns, MSI GUID regex | 3 ✅ |
| T-LPE-5 | Local IPC abuse (squatting or connecting to an agent pipe) | No named pipes or listening sockets. The helper gets an inherited anonymous pipe and takes one task. A user→service channel doesn't exist. | 3 ✅ |
| T-LPE-6 | Tampering with agent files, config or the service | Protected DACLs (SYSTEM/Administrators). Quoted `ImagePath`. Service DACL denies non-admins stop/config. Authenticode-signed binaries. | 1 ✅ / 5 (signing) |
| T-LPE-7 | Malicious process (same user) tampers with the helper | Accepted. The helper only has the user's own rights. The service treats its output as untrusted and re-checks detection. | ⚠ (by design) |
| T-LPE-8 | Zip-slip or path traversal in nested installers and portable packages | Paths canonicalized, must stay under the staging root; reparse points rejected | 3 ✅ |
| T-LPE-9 | Secrets on disk | Device key in TPM/CNG (not exportable). The enrollment token is deleted after use. Any other secret is in a SYSTEM-only, ACL-protected file or the bbolt store (DPAPI is not used). | 1 ✅ |

### TB6: Upstream supply chain (catalog and vendors)
| ID | Threat | Mitigation | Phase |
|---|---|---|---|
| T-SUP-1 | Download replaced at the vendor URL | SHA-256 from the catalog is in the signed job. A mismatch blocks the install and raises an alert. | 3 ✅ |
| T-SUP-2 | Malicious manifest in the winget community repository | Signer pins come from administrator input (the winget manifest carries none); the `verified` overlay is not populated. **Not implemented:** index MSIX signature verification (the index is fetched over TLS from Microsoft's CDN and only suggests matches; nothing installs without an audited administrator action, D98) and automatic signer-change detection. New versions held for a configurable delay in auto-update rings. Unverified packages warned about and role-gated. | 3, 5 ✅ / ⚠ residual |
| T-SUP-3 | SSRF through server-side fetching (catalog sync, content caching of admin-given URLs) | Catalog sync, the winget index and the agent installers are fetched only from fixed hosts (GitHub, Microsoft's CDN, or the mirror named in the server's own environment), never from an address an administrator types into the console; https only, size and time caps, redirects re-checked. **Two features do connect to administrator-supplied addresses:** webhooks (settings:integrations) and the SMTP server (settings:notifications). The webhook sender refuses link-local, loopback and unspecified addresses at connect time, after name resolution (D115); it never reads the answer beyond the status code; the SMTP client refuses a login over a plain connection. Agents fetch vendor URLs themselves, https only | 3 ✅ / D115 |

### TB1/TB2: Web GUI and API
| ID | Threat | Mitigation | Phase |
|---|---|---|---|
| T-WEB-1 | Credential stuffing or brute force | argon2id (m=64 MiB, t=3, p=2, with a concurrency semaphore against memory DoS); **mandatory MFA**; per-account backoff and lockout (10 failures → 15 min); per-IP rate limits; breached-password check with an offline list | 1 ✅ |
| T-WEB-2 | Session theft | `__Host-` cookie, `HttpOnly`, `Secure`, `SameSite=Strict`; 30 min idle and 12 h absolute; ID rotated on login and privilege change; MFA re-check for sensitive actions (deploy to over N devices, root unlock, role changes, creating API tokens) is **not implemented**; these need only the signed-in session. See 9f, R-5. | 1 ✅ / ⚠ |
| T-WEB-3 | CSRF | SameSite=Strict, plus a synchronizer token header on all state changes, plus an `Origin` check | 1 ✅ |
| T-WEB-4 | XSS | React escaping; CSP `default-src 'self'; script-src 'self' 'nonce-…'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'`; no `dangerouslySetInnerHTML`, enforced by a lint rule | 1 ✅ |
| T-WEB-5 | SQL injection | sqlc parameterized queries only; allow-listed dynamic-group compiler | 1 ✅ |
| T-WEB-6 | Broken access control (IDOR, cross-site, cross-org) | Every query takes `org_id` and the RBAC scope; central authorization middleware plus per-handler policy; tests for each role × endpoint | 1, 5 ✅ |
| T-WEB-7 | API token misuse | Prefixed tokens (`lp_`) for secret scanning; stored hashed; scoped; can't manage users, roles or tokens; expiry required | 5 ✅ |
| T-WEB-8 | Clickjacking, MIME sniffing, referrer leaks | `frame-ancestors 'none'`, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, HSTS (when using public TLS) | 1 ✅ |

### TB4/host: Server and data
| ID | Threat | Mitigation | Phase |
|---|---|---|---|
| T-SRV-1 | Database exposed to the network | Postgres on an internal compose network only, no published port, scram-sha-256, least-privilege roles | 1 ✅ |
| T-SRV-2 | Container escape or lateral movement | distroless non-root, `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, no Docker socket mount, tmpfs `/tmp` (resource limits are not set; configure them to your host, see RUNBOOK) | 1 ✅ |
| T-SRV-3 | Theft of key material from a volume or backup | Signing and issuing keys encrypted with the KEK (from a file on a Docker volume, never stored in the DB or image). Root key encrypted with an owner passphrase that is never stored. Backups encrypted with age. | 1, 5 ✅ |
| T-SRV-4 | Audit tampering | Insert-only database role plus a trigger; hash chain, verified on demand (console button, `admin verify-audit`). **Not implemented:** scheduled verification and SIEM streaming. From Phase 6 the running server holds only the DML-only role; the schema owner is a non-superuser held only by the `maintenance` service | 1 ✅ |
| T-SRV-5 | Default credentials | None exist. First-run setup needs a one-time setup token printed to the server log/stdout, then creates the admin with MFA. | 1 ✅ |

### TB8: Our own release pipeline
| ID | Threat | Mitigation | Phase |
|---|---|---|---|
| T-REL-1 | Malicious agent update pushed through a customer server | Agent updates need a **vendor release-key** signature (compiled in) plus Authenticode with our pinned subject, and the version can't go down. A customer server can't create one. | 5 ✅ |
| T-REL-2 | Compromised dependency | Pinned modules and lockfile, Dependabot pull requests (reviewed, never auto-merged), govulncheck, `npm audit`, gosec, semgrep, CodeQL, license allow-list, CycloneDX SBOMs per binary and for the web bundle (`cmd/librepatch-sbom`) plus a Syft SBOM of the image, reproducible builds checked by an independent rebuild, cosign-signed images and checksums (9e) | 1 ✅, 6 ✅ built and dry-run locally; the GitHub/Sigstore steps are unrun |
| T-REL-3 | Release-key theft | Release key in an HSM or cloud KMS (never on a build machine), used only by the protected `release` CI environment through OIDC, contract `scripts/release-kms.sh`; standby key compiled in from the first release; the signer must be a compiled-in key (9e) | 6 🔜 pipeline written; custody is owner decision O7 |
| T-REL-4 | Stolen release key used to pin an attacker's own Authenticode certificate | The allowed signer names are compiled into agent and server (D83), so a forged manifest needs our certificate as well as our key | 6 ✅ (unit-tested) |
| T-REL-5 | Build-system or CI compromise (a malicious workflow change, a poisoned cache, a moved tag) | Real releases only from a `v*` tag on `main`, signing jobs in a protected environment with reviewers, no build caches in the release workflow, all actions pinned to SHAs, `permissions:` minimal per job, an independent second build that must match, provenance and cosign identity naming the workflow and tag, draft release published by a person | 6 🔜 unrun; depends on repository settings (RUNBOOK 9.2) |

## 6. Server compromise: blast radius and residual risk
If an attacker gets admin GUI access, or code execution inside the server container while it's running, they can sign jobs. **No server-side design fully prevents this** for a system whose purpose is remote software installation. What we do:

1. **Typed jobs only.** There's no shell. The attacker can only install packages whose hash is in the job, uninstall, reboot or update. That's still dangerous, because a custom package upload is effectively arbitrary code. Uploads and deployments are fully audited.
2. **Agent-side policy ceiling.** Set at MSI install time and impossible for the server to raise. Examples: `ALLOWED_JOBS=inventory,wu` for sensitive servers, or `CUSTOM_PACKAGES=0` to only allow catalog packages with pinned signers.
3. **Four-eyes approval** (configurable): deployments over N devices, or of custom or unverified packages, need a second admin. Each approval needs fresh MFA.
4. **Detection.** Anomaly alerts (mass deployment, new custom package, signing-key use outside a deployment), plus the audit log streamed off-box.
5. **Root key offline-by-passphrase.** Server compromise doesn't give the attacker root operations (minting signing certs or revoking keys) unless they capture the passphrase during use.
6. **Future (post-v1):** PKCS#11/HSM for the job-signing key. Optionally, **admin-signed deployments**, where agents also require a WebAuthn-backed approval signature for custom packages.

Other accepted residual risks: falsified results from a compromised device (T-DEV-6), helper tampering by same-user malware (T-LPE-7), and a malicious upstream manifest that gets past signer pinning, for example a brand-new package (T-SUP-2).

## 7. Requirement → control traceability
| Requirement from the brief | Where |
|---|---|
| TLS 1.3 + mTLS, unique device certificates, rotation, immediate revocation | PROTOCOL §2, §7 |
| Limited-use expiring enrollment tokens, approval, rate limits | PROTOCOL §4.1, T-ENR-* |
| Signed jobs with a separate key, nonce, expiry, device ID | PROTOCOL §5, T-NET-1/2 |
| No remote shell; typed jobs only | ARCHITECTURE §5 |
| SHA-256 + Authenticode, protected staging, TOCTOU | ARCHITECTURE §7.3, T-LPE-1/2 |
| Agent ACLs, signed binaries, DPAPI/no plaintext secrets, no listening sockets, no injection | ARCHITECTURE §3.2, T-LPE-* |
| argon2id, MFA, RBAC, sessions, CSRF, CSP, rate limits, SQL, validation, OIDC-ready | T-WEB-*, DATA_MODEL |
| No default credentials, secrets from env/Docker secrets | T-SRV-5, RUNBOOK |
| Append-only audit log | T-SRV-4 |
| Container hardening | T-SRV-2 |
| Supply chain, SBOM, scanners, signing | T-REL-* |

## 8. Secure development rules (enforced in review and CI)
- No `exec.Command("cmd", ...)`, `powershell`, or shell strings anywhere in the agent. A semgrep rule checks this.
- No SQL outside `db/queries/`. No `fmt.Sprintf` near SQL. A semgrep rule checks this.
- All agent-supplied and helper-supplied data is validated at the boundary with explicit size limits.
- No secrets in the repo. gitleaks runs in CI.
- Crypto comes only from the Go standard library, `x/crypto` and Windows CNG. No hand-rolled primitives.
- Any change touching `internal/shared/envelope`, `pki`, `auth`, `userctx`, or `engine` needs a security-labelled review.

## 9. Phase 1: implemented controls and evidence

| Control | Evidence (automated unless noted) |
|---|---|
| TLS 1.3-only mTLS gateway terminated by the server; client cert checked against the DB on every handshake **and** every stream | `test/e2e` (revoked device cannot open a stream), `test/integration` (real stack) |
| Pinned-root enrollment; foreign roots, foreign leaves and wrong hostnames rejected | `internal/agent/core/tls_test.go` |
| Job-signing certificates accepted only if issued directly by the root, with the EKU; the issuing CA cannot mint one | `internal/server/pki/pki_test.go` |
| Envelope verification: signature over raw bytes with a domain prefix, device/org binding, expiry cap, replay ledger, revoked keys | `internal/shared/envelope/envelope_test.go` |
| Limited-use, expiring, hashed enrollment tokens; generic errors; per-IP/per-token limits; forced approval on hardware re-enrollment | `test/e2e` (exhausted token, re-enrollment pending) |
| Device key non-exportable in CNG (TPM when present); private key never in agent memory | `cng_windows_test.go` (Windows CI) |
| Agent: protected DACLs, quoted service path, restricted service DACL, enrollment token erased, no listening ports | Windows CI install job (`.github/workflows/windows.yml`) |
| argon2id with bounded concurrency; breach-list policy; mandatory TOTP with replay protection; recovery codes; lockout | `internal/server/auth`, `test/e2e` (replayed TOTP rejected) |
| `__Host-` SameSite=Strict session cookie; Origin check + synchronizer CSRF token; pre-MFA sessions cannot use the API | `test/e2e` (CSRF/cross-origin rejected, pre-MFA 401) |
| Strict CSP with per-request nonces; zero violations across the whole console flow | `web/e2e/console.spec.ts` |
| Parameterized SQL only (sqlc); no shells; no `InsecureSkipVerify` outside the pinned verifier; no `dangerouslySetInnerHTML` | `.semgrep.yml` in CI |
| Audit log append-only for the runtime role, hash-chained, tamper detected | `internal/server/audit/audit_test.go`, `admin verify-audit` in `test/integration` |
| Containers non-root (server), read-only rootfs, `cap_drop: ALL`, no-new-privileges; Postgres not published | `test/integration` asserts all of these via `docker inspect` |
| X-Forwarded-For trusted only from Caddy's fixed IP; spoofed header ignored | `test/integration` |
| Least-privilege DB role, KEK and DB credentials in separate Docker volumes, no default credentials (one-time setup token) | compose + `test/integration` |
| Supply chain: digest-pinned images, SHA-pinned actions, govulncheck, npm audit, gosec, staticcheck, license allow-list, gitleaks, SPDX SBOMs, a check that every action is SHA-pinned | `.github/workflows/ci.yml`, `scripts/check-actions-pinned.sh` |

**Known gaps and residual risks after Phase 1** (planned phase in brackets):
- Agent and server binaries are not yet code-signed or release-signed [5, needs O5/O7]. Until then, verify binaries by building from source.
- No WebAuthn yet (TOTP only) [5]. No API tokens yet [5]. RBAC has three org-wide roles; per-site scoping arrives in [5].
- **The agent-update signing key lives in a GitHub secret (D104).** The image workflow signs update files with `LIBREPATCH_RELEASE_SIGNING_KEY`, only for runs from `main`, and refuses to publish when the key does not match the public key built into the agents. Whoever can run workflows on `main`, or who takes over the GitHub account, can therefore sign a program that every enrolled PC will install as SYSTEM. Mitigations: two-factor sign-in on the account, write access to the repository for yourself only, review every change to `.github/workflows/`, and keep an offline copy of the key. If it leaks: build a release that trusts a new public key beside the old one (`LIBREPATCH_RELEASE_PUBLIC_KEY` accepts a comma-separated list), roll it out, then drop the old key; agents that trust only the leaked key must be reinstalled. For a stricter setup keep the key offline and sign by hand with `librepatch-release sign` (RUNBOOK 5c).
- The one-time setup token appears in the server log until setup completes. Anyone with access to container logs before setup could claim the instance; complete setup immediately after first start.
- Database traffic inside the Docker internal network is not TLS-encrypted (D28) [6 for split deployments].
- `LIBREPATCH_DEV_MODE=true` allows plain-HTTP origins, secrets in environment variables and short certificate lifetimes. It is meant for development and tests only and must never be used in production (the server logs `dev_mode:true` at start).
- govulncheck cannot run in our development sandbox (egress policy). It runs in CI.
- Agent RSS is measured informationally on Windows CI. A hard 30 MB budget check and load testing arrive in [6].
- The placeholder job-signing EKU OID uses the documentation PEN 32473 (D25).

## 9a. Phase 2: implemented controls and evidence

| Control | Evidence |
|---|---|
| Agent-supplied inventory is untrusted: strict per-field length bounds, SID/date/enum validation, NUL stripping, 25k item / 10k change / 500 user caps, sequential chunk checks, per-device rate limit; violations end the stream and are audited as `gateway.protocol_violation` | `internal/server/inventory/ingest_test.go` (`TestIngestRejectsInvalidData`), `internal/server/gateway/inventory.go` |
| Revision-checked deltas: a delta with the wrong `base_rev` changes nothing; a replay is a mismatch | `TestDeltaRevMismatchChangesNothing`, `test/e2e` (`TestInventoryEndToEnd`, `TestInventoryHelloResync`) |
| Group filters cannot inject SQL: allow-listed identifiers, all values bound, depth/node/length limits, read-only transaction with a statement timeout; fuzzed | `internal/server/groups/filter_test.go` (golden SQL, hostile payloads, `FuzzCompile`) |
| Formula-injection-safe CSV, audited exports, new `inventory:export` permission (not granted to the read-only role) | `test/e2e` (`TestInventoryEndToEnd`), `internal/server/auth` (`TestRBAC`) |
| Offline user hives are loaded with `RegLoadAppKey` from a private copy in the protected data directory (deleted afterwards); the user's original hive is verified unmodified | `internal/agent/inventory/windows_test.go` (Windows CI) |
| Inventory text is rendered by React (no raw HTML); the console CSP is unchanged and the browser test still sees zero violations | `web/e2e/console.spec.ts` |
| Tenant isolation: every inventory/group query is scoped by `org_id` (titles are per organization) | `internal/server/groups` DB test (foreign organization's device and title are never matched) |

**Known gaps and residual risks added in Phase 2:**
- The Windows collectors (registry, per-user hives, MSI, AppX, BitLocker/WMI, watchers) are verified by the Windows CI job on a runner, not yet on the full Windows 10/11/Server matrix; per-OS differences (especially AppX registry layout and WMI BitLocker availability on Home/Server editions) may surface there [3, VM matrix].
- AppX data comes from an undocumented registry layout (D33); it can silently under-report on a future Windows build.
- A compromised agent can lie about its software (it is the source of truth for itself); the inventory is therefore evidence, not an authorization input. Later phases must not gate security decisions on it without server-side corroboration.
- Group evaluation runs on demand with a 10 s timeout; a pathological filter on a 10k-device fleet may time out (returns 503) until membership caching is added if load tests show a need [6].
- `software_history` grows without retention or partitioning (D37) [6].
- CSV export reads up to 2M rows in one streaming request; it is audited and permission-gated, but there is no per-user export rate limit beyond the API limiter.
- Title normalization is heuristic: unusual names may split into several titles or merge two products; the raw name per install is always kept.
- The device Software tab renders all rows of one device (typically hundreds to ~1.5k) without pagination.

## 9b. Phase 3: implemented controls and evidence

| Control | Evidence |
|---|---|
| **Only typed, signed jobs run; no remote shell.** Jobs are Ed25519-signed at dispatch under a domain-separated prefix, verified (chain to the pinned root, signing EKU, signature, device and org, validity window, replay ledger, local policy ceiling) **before** parsing; any failure rejects the job and raises a security event | `internal/agent/jobs` (`TestRejections`, `TestReofferedJobIsNotRunTwice`), `internal/shared/envelope` tests, `test/e2e` `TestDeploymentEndToEnd` |
| **Installer integrity:** every installer carries a SHA-256 in the signed job; the file is hashed while downloading, re-opened with write/delete sharing denied and re-hashed, then Authenticode-verified (`WinVerifyTrust`) with an optional pinned signer, and only then run. A wrong hash or signer mismatch never runs the file | `TestHashMismatchNeverRuns`, `TestSignerPin`, `TestSecondSourceUsedWhenFirstFails`; Windows `TestWinVerifySignature`, `TestWinStagingDirAndLock` (Windows CI `deploy` job); `deploycheck -scenario unsigned-pinned` |
| **No argument injection:** installer arguments are an array of tokens validated against a grammar (no shell metacharacters, control characters, traversal); no `cmd.exe` or PowerShell is ever used; command lines are composed with Windows quoting rules and round-tripped; validated on the server and again on the agent. Administrator-supplied switches are held to the same grammar | `internal/shared/installer` (`TestValidateArg`, `TestCommandLineRoundTrip`, `FuzzValidateArg`, `FuzzCommandLine`), `TestOverrideValidation`, `TestMSIXAndHostileSwitchesAreFlagged` |
| **Uninstall never trusts the server's command line:** the agent derives it from its own registry row. HKLM executables must be absolute, regular files under Program Files, Windows or the Package Cache; HKCU strings are only run in that user's context | `TestUninstallRelativePathRefused`, `TestUntrustedUninstallerIsNotRunAsService`, `TestUninstallWithoutSilentCommandFailsClosed`; Windows `TestWinTrustedExecutable` |
| **Zip-slip and archive bombs:** traversal, absolute paths, symlinks, reserved device names, colliding names, entry-count and size limits (declared and actual) are refused; nothing is overwritten | `TestExtractZip`, `FuzzExtractZip`, `TestZipNestedInstaller` |
| **Per-user installs run as that user, never as SYSTEM.** The helper is started with the user's own filtered token, an explicit inherited-handle list, a kill-on-close Job Object, and no listening endpoint; it re-verifies the signed envelope, its own SID, path containment and the file hash; its result is size-capped and untrusted | `TestHelperRunsAVerifiedTask`, `TestHelperRefusals`, `TestHelperPathContainment`, `TestUserScopeWaitsForLogonThenRunsAsUser`, `TestUserScopeUninstallRunsInUserContext` (Linux fakes). **The real `CreateProcessAsUser` path is unverified, see gaps** |
| **Staging directories** are created with explicit SDDL (machine: SYSTEM and Administrators only; user: plus read/execute for that SID, under a traverse-only root) and removed after the job | Windows `TestWinStagingDirAndLock` |
| **Content authorization:** a device can fetch an uploaded installer only while it holds a live job that names that exact hash; downloads are rate-limited per device; uploads need `catalog:write`, are size-capped (2 GiB), stored by SHA-256 on a private volume and never executed by the server | `TestContentStore`, `TestCustomUploadAndPackage`, `test/e2e` deployment tests, compose test (3 MiB upload through Caddy) |
| **Unverified packages need an explicit, audited confirmation;** the confirmation flag is stored on the deployment. Custom uploads are the administrator's own content (D43) | `TestUnverifiedWingetNeedsConfirmation`, audit entries `deployment.create` (with `unverified_confirmed`) |
| **RBAC:** `catalog:read/write/override`, `deployments:read/write`, `settings:write`. Overrides (silent args, detection, pins, policies) and settings are **admin-only**; operators can import, upload and deploy; read-only sees everything but changes nothing | `internal/server/auth` `TestRBAC`, API tests |
| **Audit:** `catalog.import`, `catalog.upload`, `catalog.custom`, `catalog.override`, `catalog.remove`, `deployment.create`, `deployment.cancel`, `job.retry`, `settings.update`, `group.members` | `test/e2e` deployment tests |
| **Imported metadata is untrusted data:** manifests are parsed strictly with size and field limits; hostile switches, unknown installer types, MSIX and ZIP-without-nested-installer are flagged **unsupported** at import (visible in the console) instead of failing at runtime; fuzzed | `TestManifestRejections`, `TestMSIXAndHostileSwitchesAreFlagged`, `TestExeWithoutSilentSwitchIsUnsupported`, `FuzzParseManifest` |
| **Self-updating apps** are never fought: update deployments are refused and per-user in-place updates skipped unless an administrator sets `enforce` | `TestSelfUpdatingAppsAreLeftToTheVendorUnlessEnforced` |
| **Tenant isolation:** every catalog, deployment and job query takes `org_id`; a device may only report on its own jobs | `internal/server/deploy` DB tests |
| **Console:** job logs and package metadata are rendered by React (no raw HTML); CSP unchanged, zero violations in the browser test that walks the whole deploy flow | `web/e2e/console.spec.ts` |

| **Update cleanup cannot remove the version it just installed:** the agent re-reads the row's version and refuses to remove anything not strictly older than the target; a failed removal never blocks the update | `TestCleanupUninstallOnlyRemovesOlderCopies`, `TestUpdateRemovesOlderCopiesBeforeInstalling`, `TestUpdateKeepsCopiesTheNewInstallerReplacesInPlace` |
| **Device deletion** only for revoked/retired devices, audited, removes certificates so a stale agent cannot reconnect | `test/e2e` `TestEndToEnd` (delete section), audit `device.delete` |
| **Uninstall from inventory** needs `deployments:write`, targets only rows in that device's own inventory, refuses system components, and is derived on the device from its registry (never a server-supplied command) | `TestUninstallSoftwareRefusesSystemComponentsAndUnknownRows`, `TestDeviceRefreshAndUninstallFromInventory`, audit `software.uninstall` |

**Known gaps and residual risks added in Phase 3:**
- **The Windows-only execution paths have not run on a real multi-user Windows machine**: `CreateProcessAsUser` into another user's session, `WTSQueryUserToken`, session-change wake-ups, per-SID staging ACLs under real profiles, and Job Object tree kill with real installers. They compile, pass `go vet` and are exercised by the Windows CI `deploy` job on a single-user runner (informational, not yet observed passing). Treat per-user deployment as **experimental until the VM matrix has run** [3].
- **No package is marked verified by the project.** The VM-matrix harness exists but `matrix_results.json` is empty, so every winget package needs the audited confirmation until an administrator marks it verified (D99: `catalog:override` only, audited as `catalog.verify`, tied to the version tested). The mark is a human's judgement, not a technical guarantee; it applies to later versions of the package too [3, D52].
- Catalog installers from the winget-pkgs repository are as trustworthy as that repository's review process plus the pinned SHA-256; a malicious manifest accepted upstream would be imported as-is. The signer pin is only as good as what the manifest or administrator provides, and many vendors' installers have no stable subject to pin.
- An administrator with `catalog:write` can upload any executable and deploy it as SYSTEM to the fleet. That is the product's purpose; it is gated by RBAC, audited, and bounded by each agent's local `--allowed-jobs` ceiling, but there is no second-person approval or step-up MFA on deployment creation yet [5].
- Detection can be fooled by a lying local registry; a job's "success" is the agent's own claim (as with inventory).
- Server-side deployment rate limiting is the general API limiter; a deployment to up to 20,000 devices is allowed in one request.
- Content cache for vendor installers is not implemented (agents download from the vendor); a vendor URL that changes content after import fails the hash check and the job fails safe.
- The self-update loop guard (suspending auto-update after a flip-flop, §7.7) and `requires_elevation` helpers are not implemented; per-user installers that need elevation are marked unsupported or fail.
- Static group membership and deployment targets are not restricted per site (per-site scoping is Phase 5).

## 9c. Phase 4: implemented controls and evidence

| Control | Evidence |
|---|---|
| **Windows updates are installed only by identity from a signed job.** `WU_INSTALL` lists `(update_id, revision)` pairs; the agent installs only those that a fresh WUA search returns, never by title or by "everything pending"; counts and field lengths are validated on the server and again on the agent | `internal/agent/jobs` `TestWUInstallReportsEveryUpdateAndRescans`, `TestWUJobValidationAndCeiling`; `internal/agent/wu` `TestDevClientScansInstallsAndHides` |
| **Policy ceiling covers the new job types:** `wu_scan`, `wu_install`, `wu_hide`, `reboot` can each be disabled with `--allowed-jobs`; the server cannot raise it | `TestWUJobValidationAndCeiling` |
| **No surprise restarts:** an install job cannot demand an immediate restart; restarts from a policy never begin inside the active hours (except at an explicit deadline); every restart gives signed-in users a visible system countdown and can be aborted on the machine (`shutdown /a`); the explicit `REBOOT` job needs an online device and ≥ 1 minute of countdown; the plan is persisted so a service restart neither loses nor repeats it | `TestRebootStartsCountdownWhenDueAndNeverInsideActiveHours`, `TestRebootPlanCancelledWhenUserRestartsFirst`, `TestRebootJobIsImmediateWithCountdown`, `TestWUInstallRebootPolicies` |
| **Untrusted snapshot:** the `WU` section is size-, count- and string-limited, UUIDs and dates are validated, and a hostile report ends the stream with a `gateway.protocol_violation` audit entry; a device can only change its own `device_updates` rows | `internal/server/updates` `TestSnapshotRejectsHostileData`, `TestSnapshotBuildsCatalogAndReplacesDeviceState`; `internal/agent/wu` `TestSnapshotTruncatesAndCarriesErrors` |
| **Approval is explicit.** Updates stay pending until an administrator or an enabled rule approves them; rules never override a manual decision; every decision, rule/ring change, install, hide, hold release and restart is audited | `TestRulesApproveOnceAndNeverOverrideAnAdministrator`, `TestDecisionsAreAuditedAndHideReachesTheRightDevices`; audit actions `wu.decision`, `wu.auto_approve`, `wu.rule_*`, `wu.ring_*`, `wu.hold`, `wu.hold_release`, `wu.install`, `wu.hide`, `wu.scan`, `device.reboot` |
| **Staged rollout stops itself:** a ring whose failure rate exceeds its threshold raises a hold that keeps the update from later rings until an administrator releases it; automatic retries are bounded (3 per device and update, ≥ 24 h apart) so a broken update cannot loop | `TestRingsPilotFirstThenBroadAfterSoakAndSuccess`, `TestRingFailureRaisesAHoldUntilAnAdministratorReleasesIt`, `TestFailedInstallsAreRetriedLaterAndNotForever`, `TestGateRules` |
| **Blast radius per tick is bounded:** ≤ 500 jobs per scheduler tick, ≤ 50 updates per job, jobs expire after 7 days and release their updates | `TestExpiredJobsReleaseTheirUpdates`, `internal/server/updates/schedule.go` |
| **RBAC:** `updates:read` (every role), `updates:write` (admin, operator: decide per update, install/hide/scan/restart a device), `updates:policy` (admin only: rules, rings, source settings, hold release, checking and installing from Windows Update on the internet around WSUS) | `internal/server/auth` `TestRBAC`, `internal/server/updates` `TestDeviceActions` |
| **Policy conflicts are surfaced, never overridden:** WSUS, WUfB deferrals, disabled automatic updates or a disabled Windows Update service are detected on the device and shown to administrators; the agent never writes these policies. The one exception to "follow the device's source" is an administrator's explicit one-device **Check Microsoft online** and the install of what it found (D105): `updates:policy` only, audited as `wu.scan_online` / `wu.install_online`, one-off (not remembered by the agent), no drivers, no policy change | `TestSettingsReachEveryDeviceAndRingsAreValidated`, `internal/agent/wu` policy tests (Windows registry read-only) |
| **Console:** update titles and notes are rendered by React as text; CSP unchanged, zero violations in the browser test that scans, approves, builds a ring and rule, installs | `web/e2e/console.spec.ts` |

**Known gaps and residual risks added in Phase 4:**
- **The WUA COM code and the restart countdown have not run on a real Windows machine.** `wua_windows.go` and the `InitiateSystemShutdownEx` path compile and vet for Windows and their logic is covered by Linux fakes and the scripted dev client; the Windows CI `wu` job runs a real scan on a hosted runner but is informational and not yet observed passing. Treat Windows Update management as **experimental until the demo has been run on a real VM** [3].
- Windows Update decides what "installed" means; an update that WUA reports as installed but is superseded or fails after reboot is only noticed at the next scan. There is no loop guard beyond the 3-attempt limit.
- Driver updates are offered by Windows Update as-is; LibrePatch cannot judge a driver's safety. They are excluded by default (`include_drivers` is off, rules ignore drivers unless asked).
- Under WSUS or Windows Update for Business policy the machine may refuse or delay what LibrePatch asks for; LibrePatch reports this but does not change those policies. An administrator can check, and install from, Windows Update on the internet for one device (D105); that skips the approvals and change control of the WSUS or Configuration Manager server for that install, which is why it is administrator-only, confirmed in the console and audited. Whether a given Group Policy lets that internet scan through has not been tested on a real PC.
- Feature updates and OS upgrades are not specially handled; they appear as ordinary updates (classification "Upgrades") and are not approved by default rules unless an administrator selects that classification.
- Approvals and rings are organization-wide; per-site scoping is Phase 5. Ring membership is "first ring listing one of the device's groups"; a device in no ring is never updated automatically.
- A malicious or compromised agent can lie about scan results and install outcomes (as with inventory); the effect is limited to that device's own rows and to holding or releasing a rollout through failure counts. A device that reports failures can raise a hold for its ring's threshold only if enough devices of the ring agree.

## 9d. Phase 5: implemented controls and evidence

The backup (9d.a) and MSI (9d.b) controls follow this table.

| Control | Evidence |
|---|---|
| **A compromised server cannot make agents run its own binary.** Agents install only a release whose manifest verifies under a vendor Ed25519 key compiled into them; a build without a key rejects every update. The signature is domain-separated (`librepatch/release/v1\0`); the manifest is strictly parsed (unknown fields, trailing data, bad hash/size/version refused); platform, version monotonicity (`min_version`, `rollback_from`) and a pinned Authenticode subject are enforced; the binary must hash to the signed value (checked while downloading and again from a locked handle) and must report the promised version before the service is pointed at it | `internal/shared/release` `TestSignVerifyRoundTrip`, `TestVerifyRefuses`, `TestCheckApplicable`, `FuzzVerify`; `internal/agent/jobs` `TestAgentUpdateRefusals` (untrusted key, same version, downgrade, wrong platform, too old, hash mismatch raising a security event, wrong version output, wrong signer, rollback task cannot be armed, switch fails), `TestAgentUpdateNeedsAReleaseKeyAndPlatform` |
| **A bad update undoes itself.** The update is only switched after the rollback task is armed; a one-shot task runs the *old* binary after 10 minutes and restores it unless the new version completed a handshake (`healthy`); a state file outside the database lets the separate process decide; the job is reported failed after a rollback and succeeded only after the new version proved itself | `TestAgentUpdateSwitchesSlotsAndConfirmsAfterRestart`, `TestAgentUpdateRollsBackWhenTheNewVersionNeverBecomesHealthy`, `test/e2e` `TestAgentSelfUpdateEndToEnd`. **The Windows mechanics are unverified, see gaps** |
| **Releases reach devices gradually and stop when they fail.** One target per organization, optional pilot groups, soak time, success threshold, per-minute batch limit, maintenance window; a failing pilot pauses the rollout and writes an audit entry; 3 attempts per device and release | `internal/server/agentrel` `TestRolloutUpdatesOnlyOlderDevicesOnceAndInBatches`, `TestPilotGoesFirstThenTheRestAfterSoakAndSuccess`, `TestPilotFailurePausesTheRolloutAndAuditsIt`, `TestFailedUpdatesAreRetriedLaterAndNotForever` |
| **Uploads are checked and audited.** `releases:write` (admin) only; the bundle must verify under a key the server knows, and the file must match the signed manifest; `agent.release_add/withdraw/delete`, `agent.rollout_set`, `agent.rollout_hold` are audited. `FetchContent` serves an agent binary only to a device holding a live job whose manifest names that hash | `TestAddReleaseVerifiesTheBundleAndTheBinary`, `TestExpiredJobsAreReplannedAndWithdrawnTargetsStopTheRollout`, `TestRolloutValidation` |
| **Roles can be limited to a site.** A site binding grants only device-page permissions on that site's devices; out-of-scope devices answer 404 (no probing), jobs and events of other sites are not shown, bulk delete skips them; organization configuration, fleet-wide views, reports, audit and user administration need an organization-wide role | `internal/server/auth` `TestSiteScopedAccess`, `TestRBAC`; `test/e2e` `TestSitesUsersAndSiteScopedAccess` (devices, sub-resources, refresh, bulk delete, ten org-level endpoints answering 403) |
| **User administration cannot lock the organization out.** The last active organization-wide administrator cannot be disabled, deleted or demoted, nobody can disable or delete themselves; temporary passwords are random, shown once and must be changed at first sign-in (before any second factor); password and MFA resets end the user's sessions; every change is audited | `TestSitesUsersAndSiteScopedAccess`, `web/e2e/console.spec.ts` (technician flow) |
| **API tokens are least-privilege and revocable.** 256-bit random secret, only its SHA-256 stored, shown once; expiry mandatory (≤ 365 days); scopes limited to what the creator holds and never `users:*`; effective power = scopes ∩ the owner's *current* permissions; revocation, expiry and disabling the owner take effect immediately; tokens cannot create tokens or touch security keys; bearer requests skip the Origin check only when there is no session cookie; audit entries say `via_api_token` | `test/e2e` `TestAPITokens` |
| **Phishing-resistant second factor.** Security keys (WebAuthn) are accepted as a second factor next to the authenticator app; ceremony state is single-use and expires in 5 minutes; a key's clone warning fails the sign-in; a user always keeps one factor | `web/e2e/console.spec.ts` (registers and signs in with a virtual authenticator) |
| **Automation goes through the deployment engine.** A software policy only creates ordinary deployments (signed jobs, windows, verification, audit); policy deployments are audited as the system acting for the policy; `policies:write` is admin-only; unverified winget packages need an explicit confirmation stored on the policy; failures stop after 3 attempts | `internal/server/policies` `TestKeepUpdatedUpdatesOnlyOutdatedCopiesOnceAndRetriesLater`, `TestKeepUpdatedWaitsForTheDelayAndFollowsNewVersions`, `TestBaselineInstallsOnNewDevicesOnly`, `TestPolicyValidationAndManagement` |
| **A new software version can be made to wait for a person, and a bad rollout stops itself.** A policy with *Wait for my approval* installs nothing until `deployments:write` (administrator or operator) approves that exact version; declining, undoing and every hold and release are audited with who and why. A policy that rolls out in stages sends a version to a ring only after the ring before it met its success threshold, and a ring that fails raises a hold that only `policies:write` (administrator) can release (D121). The approval and the hold are enforced on the server when a job is created; the signed job itself is unchanged, so an agent cannot tell, and does not need to. | 
| **Catalog overlays are signed, scoped and cannot be rolled back.** An overlay (silent arguments, detection rules, verified marks) is accepted only if it verifies under the public key the administrator entered for that source; there is no built-in key. Silent arguments pass the same argument grammar as an administrator's override, an older document than the source already has is refused, a refused or failed document leaves the previous one in use, and an overlay cannot set policy (pin, exclusion, per-user or self-update policy). Fetching refuses loopback and link-local addresses and caps the body at 2 MiB. Managing overlays needs `catalog:override` and is audited (D122). | 
| **Vulnerability matching sends nothing about the fleet anywhere.** The server downloads the public CISA and NIST lists (off until an administrator turns it on, from addresses that can be a local mirror, never from loopback or link-local addresses, with size and request limits and a refusal of empty or damaged files) and matches them against inventory it already holds; there is no upload, no telemetry, and the lists themselves are data, not code. The NVD API key is a sealed secret. Syncing, importing and mapping changes need `settings:integrations` and are audited; viewing needs `reports:read` (the device tab, access to the device). Known limits: matching is only as good as the CPE names in the mapping, and a feed an attacker controls (a hostile mirror address an administrator entered) could hide or invent vulnerabilities in the console but cannot run anything (D123). | 
| **Messages to the user cannot be used to close arbitrary programs.** The programs come from the package (administrator override or signed overlay), not from the deployment; the signed job carries them; the agent re-validates the names (plain `name.exe`, at most 10), refuses a protected list (Windows' own processes, the shell, installers, the agent), only touches programs in a signed-in user's session (never session 0), asks politely (`taskkill` without `/F`, as that user) before ending anything, and checks the pid against the image name before ending it. Questions are `WTSSendMessage` boxes; no helper code runs in the user's session and nothing the user types is executed. Off unless chosen; `deployments:write` / `policies:write` and the audit entry carry the choice | `internal/agent/jobs` `TestValidatePrompts`, `TestServiceSessionAndUnknownStateAreLeftAlone`, `internal/shared/installer` process name checks, `internal/server/deploy` `TestPromptsReachTheSignedJob`. The Windows implementation (`prompts_windows.go`) is compiled and vetted, **not run on a real PC** |
| **Wake-on-LAN and read-only views are narrow by construction.** A wake job makes an agent send a magic packet only to the broadcast address of an interface network that contains the target's last address, so it cannot be aimed at another network; a view reads and changes nothing (services are opened for query only), excludes the Security event log at the console, the server and the agent, and its answer is kept apart from the job result, readable only with `devices:inspect` (administrators), size-capped, validated as JSON of a known kind and deleted after an hour. Both job types obey the agent's local `--allowed-jobs` ceiling | `internal/agent/jobs` `TestWakeSendsTheMagicPacketOnTheMatchingNetworkOnly`, `TestWakeRefusesAComputerOnAnotherNetwork`, `TestInspectBodiesAreValidatedAndTheSecurityLogIsNeverOffered`, `TestInspectViewsAreSizeCapped`; `internal/server/updates` `TestInspectJobsAndTheirPrivateData`, `TestMalformedViewDataIsDropped`. The Windows implementation (`inspect_windows.go`) is compiled and vetted, **not run on a real PC** |
| **The peer cache cannot change what runs, and does not open the cache to the network.** Whatever a peer sends is hashed against the SHA-256 in the signed job like any download; a peer is reached only at a private IPv4 address, only with a device certificate of this installation (checked both ways), and serves only files it has already verified, by hash, only to its own networks; off unless the organization turns it on, and an agent whose `--allowed-jobs` leaves out `peer_cache` never shares. Opening the port is a Windows Firewall rule for the private and domain profiles | `internal/agent/peercache` `TestAPeerServesAFileToADeviceOfTheSameInstallation`, `TestADeviceOfAnotherInstallationOrNoCertificateIsRefused`, `TestOnlyTheLocalNetworkIsServed`, `TestValidURL`, `TestPutOpenAndTheHashMustMatch`; `internal/agent/jobs` `TestAPeerThatSendsTheWrongBytesIsSkippedAndNothingIsKept`, `TestPeerSourcesAreValidatedBeforeTheJobIsAccepted`; `internal/agent/core` `TestTheLocalCeilingKeepsSharingOffWhateverTheServerSays`. The firewall rule and real transfers are **not tested on Windows** |
| **The audit log can be searched, exported and proven.** Filters (action prefix with escaped wildcards, outcome, actor, target, time), a chain verification that audits itself, CSV export capped at 100,000 rows with spreadsheet-formula neutralization | `web/e2e/console.spec.ts` (verify, filter), `internal/server/api` route/spec test |

**Known gaps and residual risks added in Phase 5:**
- **Self-update on Windows is unverified.** The service image-path switch, the scheduled task (`schtasks /XML`), the non-zero-exit restart (needs "failure actions on non-crash failures") and the Authenticode comparison compile and vet for Windows and run in the Linux simulation, but have not run on a real machine. A Windows CI job (`selfupdate`) and `docs/demos/PHASE5-DEMO.md` Part B/C are the verification path; treat self-update as **experimental until they pass** [3].
- **The vendor release key does not exist yet** (O7) and the code-signing certificate (O5) is open. Builds without a key refuse every update; development builds are unsigned and `RequireAuthenticode` is off. Until a real key and certificate exist, nothing in this tree can be shipped as a trustworthy update channel.
- **The rollback is time-based** (10 minutes). If the server is unreachable for that long right after an update the agent rolls back although the new version is fine; the server then retries (up to 3 times). Agents older than Phase 5 cannot update themselves and must be reinstalled once.
- **Site scoping is deliberately narrow** (D71): there is no per-site view of reports, audit, software search or deployments, and no per-site pilot or policy. An organization-wide read-only role sees every site.
- **API tokens** have no IP allow-list and are not MFA-gated at use (the MFA happened when the owner created them); a stolen token works until revoked or expired. Keep scopes minimal and lifetimes short.
- **Security keys:** no attestation policy (any authenticator is accepted), user verification is "preferred", and keys are bound to the console's public hostname, so changing `LIBREPATCH_PUBLIC_URL` invalidates them (use the authenticator app or an MFA reset). Tested with a browser virtual authenticator, not with hardware.
- **Temporary passwords are handed over by a person** (there is no e-mail); anyone who sees one before the user changes it can sign in as the user up to the point of the second-factor enrollment, which they would also have to complete. Prefer a channel you trust.
- **Policies act at scale:** up to 200 devices per policy per 5-minute run, no second approver. Restrict `policies:write` (admin) and scope policies to groups you trust.
- **Compliance numbers are only as good as the devices' own scan reports** (a compromised agent can claim compliance).

## 9d.b MSI

Scope: the Windows MSI that wraps `librepatch-agent.exe install` / `uninstall` for GPO, Intune and RMM deployment (`installer/windows`, decision D67).

| Control | Evidence |
|---|---|
| **Narrow interface.** The only public properties are `SERVER`, `TOKEN`, `ALLOWEDJOBS`. Launch conditions deny every printable ASCII character that is not valid in each (no quotes, spaces, ampersand, pipe, angle brackets, caret, percent, semicolon, dollar and so on); `SERVER` must contain `:`, `TOKEN` must start with `LP1.`. The agent validates all three again (`config.FromBundle`, `config.ParseAllowedJobs`). | `installer/windows/package_test.go` (`TestLaunchConditionsFitAndCoverTheDenyList`, `TestLaunchConditionBehaviour`: a small evaluator of the MSI condition subset checks every ASCII character) |
| **No shell, no script.** All three custom actions are `WixSilentExec64` (util extension) starting `librepatch-agent.exe` directly, `Execute` deferred or rollback, `Impersonate=no` (LocalSystem). No `cmd.exe`, PowerShell, VBScript/JScript, or extra binary. | `TestCustomActionsNeverUseShellsOrScripts` |
| **Token handling.** `TOKEN`, the `--token` argument property and the CustomActionData property are `Hidden` (MsiHiddenProperties); the token reaches the elevated action only as CustomActionData; `WixSilentExec64` logs neither the command line nor the child's output; `librepatch-agent install` does not print the token. **Known exception (D103):** Windows Installer itself writes the install action's data, token included, in clear into a verbose log (`/l*v`), on the line `Executing op: CustomActionSchedule(Action=InstallAgent ...)`, although the property is hidden. | `TestTokenIsHiddenEverywhereItTravels`; CI job `msi` greps the verbose logs (ANSI and UTF-16) for the token and fails if it appears anywhere except on that one known line |
| **Clean failure.** A failed fresh install (bad token, unreachable server, unknown job type) exits 1603 and a rollback action runs `uninstall`; it is scheduled only when no agent service existed before the run, so it can never wipe an enrolled machine. | CI job `msi` failure cases (six), checks service, `ProgramData\LibrePatch`, `Program Files\LibrePatch` and the staging directory are gone |
| **No re-enrollment on upgrade.** A major upgrade skips the old package's uninstall (`UPGRADINGPRODUCTCODE`) and runs `install --if-not-installed`, which exits 0 when the service and `config.json` exist. | `internal/agent/install` `TestInstalledIn`; CI job `msi` upgrade step (same device ID, one device row, one ARP entry) |
| **Staged binary is not user-writable.** `%ProgramFiles%\LibrePatchSetup\` inherits the Program Files ACL (Users: read and execute only). Per-machine, elevation required, x64 and Windows 10 1809+ / Server 2019+ enforced by launch conditions. | Package.wxs; not asserted by a test |
| **Pinned, key-free build.** WiX 7.0.0 and its Util extension are pinned; the build scripts contain no certificate or secret; signing is a documented hook (`-SignScript`) run by the release pipeline. CI actions are pinned by SHA. | `TestToolchainIsPinnedAndConsistent`, `TestWorkflowJobMSI` |

**Known gaps and residual risks:**
- **The MSI has not been built or run on Windows by the author.** WiX v7 cannot bind an MSI on Linux (its binder loads `msi.dll`), so only the WiX compile and link phases and the XML-level Go tests ran locally. The CI job `msi` is informational (`continue-on-error`) until it has been seen passing; nothing above marked "CI job msi" is verified yet.
- **The token is on the `msiexec` command line.** It is visible to local administrators in the process list during the install and in whatever your tool records: the Intune Management Extension log, RMM job history, GPO scripts and transforms (SYSVOL is readable by all authenticated domain users). Mitigation is operational: a multi-use token per wave, short expiry, device approval on, revoke after the wave (RUNBOOK section 4). **Confirmed in CI (Windows Server 2025 runner): with `/l*v`, Windows Installer writes the install action's command line, including the token, in clear into the log, even though `TOKEN`, `AgentArgsToken` and `InstallAgent` are in `MsiHiddenProperties`.** The owner accepted this (D103): an enrollment token expires, has a use limit and can be revoked. Without `/l*v` there is no log. Treat any verbose MSI log from an install as secret until the token has expired or been revoked, and do not attach one to a bug report.
- **The deny lists are not a whitelist.** MSI conditions have no regular expressions, so unusual non-ASCII input and `[` / `]` are not rejected by the MSI; they are rejected by the agent. The command line is never interpreted by a shell, so this is defense in depth.
- **An install-step failure has a generic MSI message** (1603 and the log). The reason is not in the MSI log (WixSilentExec64 discards the child's output); it is in the agent log until the rollback removes it, or from running the exe by hand.
- **Uninstall is best effort.** A failure of `librepatch-agent uninstall` does not block removal of the MSI entry (otherwise a broken agent could not be removed); the service may remain and must be checked.
- **The MSI does not update the slot binaries.** After a major upgrade the staged exe is newer than `slot-a`; the agent's own update mechanism (ARCHITECTURE section 10) is what updates the running agent.
- **MSI signing is not done in this repository.** An unsigned MSI triggers SmartScreen and may be refused by AppLocker/WDAC policies until the release pipeline signs it.
- **WiX v7 is under the OSMF EULA.** Accepting it is a legal act of the project owner; revenue-generating users at or above US$10k a year owe the maintenance fee unless they pay for WiX support elsewhere. This repository only records the acceptance in the build scripts (D67); it is not legal advice.
## 9d.a Backup and restore

`librepatch-server backup` / `restore` (`internal/server/backup`; procedure in RUNBOOK §6). Backups concentrate everything an attacker would want, so they are encrypted by construction and checked hard on the way back in.

| Control | Evidence |
|---|---|
| **No plaintext backups.** A backup needs at least one age recipient (X25519 or hybrid public key) or a scrypt passphrase; with none, nothing is written. Recipients and passphrase cannot be mixed. Passphrases come only from a file (`--passphrase-file` / `LIBREPATCH_BACKUP_PASSPHRASE_FILE`), never from argv or a plain environment variable, and must be ≥ 12 characters. A secret key pasted as a recipient is rejected without echoing it | `TestBackupRefusesWithoutRecipient`, `TestCLIRefusesUnencryptedAndBadInput`, `TestRecipientParsingNeverEchoesSecrets` |
| **The master key and the database passwords are never in the archive** (stated in every manifest). A backup alone cannot open the CA keys or TOTP secrets, which are sealed with the KEK; the KEK must be backed up separately | `NotMasterKey` in the manifest notes; RUNBOOK §6.1 |
| **Confidentiality and integrity of the stream:** age (X25519/ChaCha20-Poly1305 chunks, final-chunk marker), so tampering, truncation and appended data are detected; the restore reads the encrypted stream to its authenticated end before it commits | `TestWrongKeyAndTamperedCiphertext` (flipped bytes, truncation at several points, trailing garbage, plaintext) |
| **Every part is bound to the manifest.** The last archive member lists the SHA-256 and size of each other member and the row count of each table; header and manifest must agree; order and numbering of parts are enforced; nothing may follow the manifest. A restore fails before COMMIT if anything differs, so a rewritten member (valid encryption, wrong hash), a dropped, added or reordered part leaves **no rows behind**. When the input is a file the whole archive is also verified before the database is touched | `TestTamperedMemberWithValidEncryption` |
| **Hostile archives are treated as untrusted data** (anyone who knows the public key can produce a decryptable file): member names must be one of the fixed forms; content paths must be clean, relative, forward-slash, without `..`, hidden components, control characters, backslashes or drive colons; only regular files (no symlinks, hard links, directories, devices, sparse files); duplicates refused; files are written through `os.Root` into a staging directory under the content directory, so nothing can land outside it, and are renamed into place only after verification; table and column names from the header are checked against the live schema and always quoted | `TestUnsafeMemberNamesAndTypesAreRefused`, `TestTraversalWritesNothingOutside`, `TestHeaderValidation` |
| **Bounded resource use:** header 4 MiB, manifest 64 MiB, ≤ 200,000 members, chunk 64 MiB, file 16 GiB, 8 TiB in total, ≤ 256 MiB for one row; table data is cut into 8 MiB chunks so memory stays bounded and content files are streamed. Headers that declare more than the caps are refused before any data is read. Fuzz tests cover the tar/manifest reader | `TestSizeCapsAreEnforcedFromHeaders`, `TestChunkerSplitsOnRowBoundaries`, `FuzzWalker`, `FuzzManifest` |
| **Consistent snapshot, no server stop:** all tables are read in one `REPEATABLE READ READ ONLY` transaction | `TestBackupIsConsistentSnapshot` |
| **Audit-log integrity survives a restore.** `audit_log` rows are copied byte for byte (its append-only triggers fire on UPDATE/DELETE/TRUNCATE only; other user triggers are switched off during the load and back on afterwards). After the restore the hash chain is verified with the normal `audit.Verify`; a broken chain is reported as an error and exit status 1. Both operations are audited (`admin.backup`, `admin.restore`) | `TestRoundTripFreshSchema` (table-by-table comparison, `audit.Verify`), `TestCorruptAuditChainIsReported` |
| **Restore never merges into live data.** It refuses a database that has any row in any application table, a schema newer than the backup, or a schema without migration history; replacing needs `--force --wipe` (drops the `public` schema). It locks all tables (a running server blocks it rather than racing it). A backup from a newer release, or of an unknown format version, is refused with a message naming what to do | `TestRestoreRefusesNonEmptyTarget`, `TestRefusesNewerSchemaAndUnknownFormat` |
| **Wrong master key is caught at restore time:** the KEK from the environment is tried on the sealed CA keys inside the restore transaction (override: `--skip-kek-check`) | `TestWrongMasterKeyFailsRestoreAtomically` |
| **Least privilege and process hygiene:** uses the schema-owner (migrator) URL only, never needed by the running app; `--out` is written to a temp file with mode 0600, fsynced and renamed (stdout mode writes the archive and nothing else, logs go to stderr); an interrupted or failed backup leaves no file | `TestCLIPassphraseMode`, `TestCLIStdoutAndStdin`, `TestCLIRefusesUnencryptedAndBadInput` |

**Known gaps and residual risks:**
- **No sender authentication.** age public-key encryption proves nothing about who made a file: anyone who knows a recipient key (not secret) and can place a file in the backup store could forge a backup (new admin, fake devices, a rewritten audit chain that verifies, because the hash chain is unkeyed). Protect the backup store's *write* access (append-only/object-lock buckets, a separate account), compare file hashes recorded elsewhere, and treat a restore as a trusted operation done by an administrator who knows where the file came from. Signing backups (for example with a key derived from the KEK) is a possible later hardening.
- Whoever holds an age secret key (or the passphrase) can read the entire backup, which includes password hashes, sealed key material, device inventory and the audit log. Keep that key offline and separate from the backups. The sealed keys in a backup are still protected by the KEK, but password hashes (argon2id) and TOTP secrets are only as safe as the KEK.
- The hash chain cannot detect **truncation at the end** of the audit log in a restored database (dropping the newest entries leaves a valid chain); the same limit applies to the live log. Compare entry counts with a trusted record when it matters.
- A restore is only as good as its latest backup: nothing recorded after it exists (enrollments, approvals, jobs, audit entries). An agent enrolled after the backup holds a certificate from the same CA but has no device record and is refused.
- Content files are read after the database snapshot, so a custom package uploaded in between is in the files but not in the database (harmless extra), never the reverse. The content directory itself is trusted storage: a file replaced there before the backup is backed up as is (installers are separately pinned by hash in the database and re-checked by agents).
- The archive is not compressed; large installer sets make large backups.
- `--wipe` drops everything in the `public` schema, also objects LibrePatch did not create; the flags are the only guard.
- Partitioned tables are supported (the parent is dumped and reloaded through the parent, partitions are not listed), but a partition that does not exist in the target schema fails the load. Foreign-key cycles between tables are not supported and make the backup fail with a clear message (a test fails first if a migration introduces one).
- Not yet verified: restore into a different PostgreSQL major version than the one that made the backup (the format is COPY text, which is portable, but only PostgreSQL 16 was tested), and backups of databases larger than the test data (the design streams, but no multi-GB run was made).

## 9e. Phase 6: release pipeline (supply chain)

Written in Phase 6 and exercised **locally** with throw-away keys (`scripts/release-dryrun.sh`); the GitHub workflow, the cloud signing steps and the MSI build have never run. Design: DECISIONS D79-D84; operator guide: RUNBOOK section 9; customer checks: `docs/VERIFYING_RELEASES.md`.

| Control | Evidence |
|---|---|
| **Reproducible builds.** Same commit, different directory, time zone, locale, umask and build cache: byte-identical Go binaries (agent, server, tools), web bundle and SBOMs; `release.yml` repeats the build on a second runner and fails on any difference | `scripts/build-release.sh`, `scripts/verify-reproducible.sh` (run locally, two builds of the same commit, identical; it caught and we fixed an umask-dependent file mode in the web archive) |
| **Pinned inputs.** Go toolchain from `go.mod` (the script refuses another), Node major, lockfile install without scripts, base images by digest (`deploy/Dockerfile.server`, which now fails if the base image's Go release is not the expected one), actions by commit SHA | `scripts/check-actions-pinned.sh` (CI `lint`), Dockerfile `EXPECT_GO_VERSION` |
| **SBOMs.** CycloneDX 1.5 for each Go binary (the modules actually linked, with `go.sum` hashes), the web production closure (integrity hashes, licenses) and the image; deterministic; shape-checked | `internal/sbom` tests (`TestRealWebLockfile`, determinism, rejection of malformed documents), `librepatch-sbom check` in `verify-release.sh` |
| **The release key never leaves the KMS.** The pipeline obtains bytes (`librepatch-release tosign`), a KMS signs them with pure Ed25519, `attach --pub` and `verify` re-check the result | `cmd/librepatch-release` tests; `release-dryrun.sh` runs the same path with a throw-away key and with a fake `aws` command, and shows that a wrong key is refused at `attach` and a tampered binary at `verify` |
| **A stolen release key is not enough.** The allowed Authenticode signer names are compiled in | `internal/shared/release` `TestAuthenticodeSubjectsCompiledIn`; `release-dryrun.sh` shows a release-built tool refusing a foreign signer |
| **Signed, attested artifacts.** Authenticode for the agent and MSI (agent first, then the MSI built around it), cosign keyless signature of `SHA256SUMS`, cosign SBOM attestations, GitHub build provenance, image signed by digest and checked to contain the released server binary | `.github/workflows/release.yml`, `scripts/authenticode.ps1`, `scripts/verify-release.sh` (**unrun** for everything that needs GitHub, Sigstore or Windows) |
| **Least privilege.** Workflow `permissions: {}` with per-job grants, no caches, signing only in the protected `release` environment (OIDC, no stored cloud credentials), real releases only from tags on `main`, draft release | `release.yml` |

**Known gaps and residual risks added in Phase 6:**
- **Nothing here has produced a real release.** There is no release key (O7), no code-signing certificate (O5), no `release` environment configured, and `release.yml` has never run on GitHub. The pipeline's own failure modes (a wrong action input, a missing runner tool, an Azure/AWS permission) will appear on the first dry run.
- **Azure Key Vault is not known to support Ed25519.** The Azure hook assumes it does; if not, use AWS KMS, Google Cloud KMS or an HSM through another provider function.
- **The signed Windows files are not reproducible** (signature and timestamp) and the repository ships no tool to compare a signed PE with its `unsigned-SHA256SUMS` entry through the Authenticode digest. The MSI is not part of the reproducibility check. Whole-image reproducibility is unverified (BuildKit `rewrite-timestamp`; BuildKit itself is not pinned by digest). The `windows/arm64` agent is not built or shipped by default.
- **No vendor key revocation channel.** Revoking or rotating the release key needs a release signed by a still-trusted (standby) key; agents offline across a rotation need a reinstall (RUNBOOK 9.4). The compiled-in signer names have the same property.
- **SBOM limits:** the Go dependency graph is flat, Go modules carry no license data, and the Go module hash is the `go.sum` dirhash, not an archive digest. A vulnerability scan of an SBOM is only as good as its purls.
- **Sigstore keyless trust** rests on GitHub's OIDC issuer, Fulcio and the Rekor log being honest and available; verification needs network access to the trust root unless the customer mirrors it.
- **Action pinning is by SHA of a tag at the time of writing**; the SHAs were resolved from the upstream repositories at authoring time and are re-reviewed when bumped. Third-party actions still run with the job's permissions, so the signing jobs keep their list short (Microsoft's signing action, `azure/login`, AWS credentials, cosign installer, GitHub's attestation action).

## 9g. Phase 6: licensing (removed)

Phase 6 added offline-verifiable license keys and a device cap. LibrePatch is now open source (decision D100), so that
mechanism, its threat-model rows and its residual risks no longer exist. Nothing in the product limits the number of devices,
and nothing contacts the vendor (O9 stands). Migration 00018 drops the `licenses` and `license_clock` tables.

## 9h. Phase 7: branding

Per-deployment branding (`internal/server/branding`, `internal/server/api/branding.go`, migration `00010_branding`; decision D92, operations in RUNBOOK §5g). It adds an upload feature and public text, so it is reviewed as an input-handling surface.

| Threat | Control | Evidence |
|---|---|---|
| **Script via a logo** (SVG with `<script>` or `onload`) | SVG is refused outright (415 for the declared type, 422 for SVG bytes sent as PNG). Only PNG and JPEG recognised by content are decoded, then re-encoded as PNG by the server, so what is stored and served is pixels only | `TestProcessRejects`, `TestBrandingAdministration` |
| **Polyglot or metadata payload** (bytes after IEND, `tEXt`/`eXIf` chunks, JPEG comments) | Decode and re-encode drops every ancillary chunk and anything after the image; the output is checked to end at its own IEND | `TestProcessStripsEverythingButPixels`, e2e asset assertions |
| **Decompression bomb / oversized upload** | 512 KiB body cap (413), dimensions read from the header and limited per slot before any pixel is decoded, stored size re-checked after encoding; fuzzed | `TestProcessDecompressionBomb`, `FuzzProcess` |
| **Browser treats an image as something else** | Always `Content-Type: image/png`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`, `Cross-Origin-Resource-Policy: same-origin`; the asset kind is checked against a fixed list, and assets live in the database, never on a path | e2e header assertions, path-like kind returns 404 |
| **Stored XSS in texts** (headline, message, footer, names, report footer) | Plain text only, length limits, control and bidi characters refused; React escapes them on the console and `html/template` on the report; the index page embeds the branding as `application/json` with `<` escaped (never executed; the CSP has no inline script) | `TestValidateRejects`, e2e report test (`<script>` escaped) |
| **Dangerous support link** (`javascript:`, `data:`, credentials in URL) | https only, no userinfo, no quotes/whitespace/backslashes, 300 characters | `TestValidateRejects` |
| **CSS injection via a color** | Strict `#rrggbb` only, lower-cased, also enforced by a database CHECK | `TestValidateRejects`, `TestBrandingMigrationIsReversible` |
| **Unreadable or invisible UI via a color choice** | Contrast rules (WCAG AA) enforced server-side and mirrored in the browser; a failing combination cannot be saved | `TestAccentChecks`, `TestBlockedColorsAreRejected`, `contrast.test.ts` (shared vectors) |
| **Non-administrators or tokens changing the look of the product** (phishing the sign-in page) | `branding:write` is administrator-only, cannot be put in an API token, needs the session, MFA and CSRF token; every change is audited with before/after | `TestRBAC`, `TestBrandingAdministration` (operator, read-only, anonymous, token, missing CSRF) |
| **Information exposure by the public endpoint** | `GET /branding` returns only display values and image links (what the sign-in page shows); the report footer, user data and device data are not in it | `TestBrandingAdministration` |

**Known gaps and residual risks:** an administrator can still make a convincing look-alike sign-in page for their own deployment (that is the feature); the public support contact and legal text are visible to anyone who can reach the server; images are not scanned beyond decoding; the report is a printable HTML page, not a PDF, so its signature of origin is the server's TLS identity only.

## 9i. Phase 8: console appearance

Themes, preferences and the redesigned console (decision D93). New attack surface is small: one blocking script, one per-user JSON document, and an administrator-set theme list.

| Threat | Control | Evidence |
|---|---|---|
| **Inline script for the no-flash theme** would force `script-src 'unsafe-inline'` | The theme is applied by a same-origin file (`/theme-init.js`, covered by `script-src 'self'`); the CSP stays free of `unsafe-inline` for scripts. Inline `style` attributes set by script go through the CSSOM, which `style-src` with a nonce allows | GUI end-to-end test fails on any CSP violation; `theme-init.test.ts` |
| **Stored XSS / injection through preferences** (theme id, view names, view state) | The theme id must match `^[a-z][a-z0-9-]{0,31}$` and is used only as an attribute value and a lookup key, never as HTML or CSS; view names are plain text (no control characters, 60 characters); view state must be a JSON object of at most 4 KiB, 20 views per table, 32 tables, 64 KiB per account (also a database CHECK) | `TestPreferencesAndThemePolicy`, `TestBrandingMigrationIsReversible` |
| **One person reading or changing another's preferences** | `/me/preferences` acts only on the signed-in person; a bearer API token cannot change it | `TestPreferencesAndThemePolicy` |
| **Bypassing the administrator's theme limits** | The server refuses a theme the organization does not offer; the console falls back to the organization default when a saved theme is no longer offered | `TestPreferencesAndThemePolicy`, `themes.test.ts` |
| **Unreadable interface (a11y as a safety property for clinicians)** | Every theme token pair is checked against WCAG AA; the branding accent is adapted per theme; axe scans every page the end-to-end test visits | `themes.test.ts`, GUI end-to-end test |
| **Fonts or icons fetched from a third party** | Inter and the icons are bundled; there are no runtime network requests (CSP `font-src 'self'`, `connect-src 'self'`) | build output, CSP |

**Known gaps:** a person's own theme is cached in the browser's local storage until they sign out (cleared on sign-out); saved views are opaque to the server beyond their size and shape.

## 9j. Secrets that create themselves (D109)

The stack makes its own database passwords and master key on first start, so there is no setup script. What this changes for
the threat model, and the evidence:

| Control | Evidence |
|---|---|
| **Each service sees only its own secrets.** Separate volumes: `secrets_pg` (database passwords: the database container only), `secrets_app` (runtime login: server and maintenance, read-only), `secrets_owner` (schema owner: maintenance only, read-only), `secrets_key` (master key: written by maintenance, read-only for the server). The server never holds the schema-owner credential (T-SRV-4) and the database container never sees the master key | `test/integration/compose_test.go` (inspects the mounts of the running containers; runs on GitHub, not in the development sandbox) |
| **A master key is never replaced by accident.** It is created only by `maintenance migrate` with `LIBREPATCH_MASTER_KEY_AUTOGEN=true`, with an exclusive create (mode 0400), and only if the database holds no sealed data (CA material, setup state, TOTP secrets). A missing key file next to an existing database is an error that says how to restore the key, never a reason to make a new one. Passwords are likewise never invented for a database that already exists | `masterkey_test.go` (`TestProvision...`), `test/deployscripts` |
| **The key is shown to the first administrator, once, and must be confirmed.** `GET /security/master-key` needs `settings:write` and MFA, is `no-store`, and answers 404 after the acknowledgement; `POST /security/master-key/acknowledge` needs the last six characters of the key. Until then every other API call answers 403 `master_key_unconfirmed` (only the session, logout, the two key calls and preferences work). Viewing and acknowledging are audited with the key *id* (the first four bytes of its SHA-256), never the key. The in-memory copy used for display is cleared after the acknowledgement | `test/e2e/masterkey_test.go`, `web/e2e/console.spec.ts` |
| **The `maintenance` service now stays running (D111).** It used to be a one-shot container that exited after migrating. It now idles afterwards so that container managers show every container as up. It still holds the only copy of the schema-owner login (mounted read-only from `secrets_owner`) and the writable `secrets_key` volume, but for the whole lifetime of the stack instead of a few seconds; it sits on the internal backend network, publishes no ports, runs as a non-root user on a read-only filesystem with all capabilities dropped, and opens no database connection after the migrations. The server still never holds the owner login | `test/integration/compose_test.go` (maintenance running and healthy), `cmd/librepatch-server/main_test.go` |
| **Residual risk.** Until it is acknowledged, the key sits in server memory and is visible to the signed-in administrator; the key file stays on the Docker volume readable by the server container (as the file under `deploy/secrets` was before), so root on the Docker host can read it. The screen is a prompt to keep a copy elsewhere; it cannot check that the copy really exists | stated here |

## 9k. Agent downloads from the server (D112)

The server fetches the Windows agent (exe and MSI) from the project's GitHub release that matches its own version and serves them at
`/download/librepatch-agent.msi` and `/download/librepatch-agent.exe`, so that PCs never need to reach GitHub.

| Control | Evidence |
|---|---|
| **What is fetched, and from where.** Only the two files of the release `server-<own version>`, over HTTPS (redirects must stay on HTTPS, at most 5), each at most 256 MB, written to a temporary file and moved into place only after the check. Development and edge builds (no release) fetch nothing. A mirror can replace GitHub (`LIBREPATCH_AGENT_DOWNLOAD_BASE_URL`, https; plain http only with `LIBREPATCH_DEV_MODE`) | `internal/server/agentdl/agentdl_test.go` |
| **Integrity check.** The SHA-256 published beside each file must match; a mismatch discards the download and nothing is offered. A file with no published hash (releases made before the MSI hash was published) is kept and shown as "computed by this server", not "verified". A stored file is re-hashed at every start and fetched again if it no longer matches | `TestAWrongHashIsRefused...`, `TestStoredFilesAreNotFetchedAgainUnlessDamaged` |
| **What this does not give.** The hash and the file come from the same release page, so it catches a damaged download, not a compromised release or account; the files are not Authenticode-signed (as before). Someone who can change the server's content volume could replace the stored file (the re-hash uses a hash kept in the same folder). Closing the first gap (checking the exe against the signed `.lprel`, or a hash baked into the server image) is possible later | stated here |
| **The download addresses are public.** No sign-in, because a PC has none; the files are public on GitHub anyway and contain no secret (the enrollment token and the CA pin are in the command, not in the file). They are rate limited per address (the API limiter) and sit outside the console IP allow-list on purpose. Serving a stored file costs the server nothing but bandwidth; nothing a request carries is used to fetch anything | `test/e2e/agentdl_test.go` |
| **The list needs a session.** `GET /api/v1/agent-downloads` needs `enrollment:read` | `TestAgentDownloadsListNeedsASession` |
| **Where it is kept.** A dot-folder (`.agent-downloads`) on the content volume: backups skip dot-folders, so backups do not grow by about 30 MB; after a restore the server fetches the files again | `internal/server/backup` (skips dot entries) |

## 9l. Code review (D115)

A review of the server and agent aimed at administrator permissions and remote fetching, with fixes. Windows-only agent code was
read and cross-compiled (`GOOS=windows go build/vet`), not run.

| Finding | Fix | Evidence |
|---|---|---|
| **An API token could read and confirm the master key.** `settings:write` is a scope a token may carry, and it opened `GET /security/master-key` and its acknowledge call, which are allowed while the key is unconfirmed. A script could read the key, type its last six characters and clear the warning | Both routes now refuse an API token (403): only a signed-in console session may handle the key | `TestMasterKeyRefusesAPITokens` |
| **Event streams outlived the caller's rights** (R-6): a revoked or expired API token, a disabled account or a removed role kept receiving fleet events until the browser reconnected | The stream re-authenticates from the database every minute (`reauthenticate`) and ends when the caller is gone; role changes take effect at the next check | `TestReauthenticateFollowsTokenUserAndRole` |
| **A full rate-limiter table was emptied** ("fail open on memory"), so someone filling it with made-up keys also reset the bucket of an account under attack | The least recently seen tenth is dropped instead; keys in use keep their buckets | `TestLimiterKeepsBusyKeysWhenFull` |
| **Webhooks could reach the server's own listeners.** Only link-local addresses were refused, so `http://127.0.0.1:...` or `0.0.0.0` could be used from the settings page to make the server call itself | Loopback and unspecified addresses are refused too, on the address actually dialled | `TestRefuseLocalTargets`, `TestPosterDoesNotReachLoopback` |
| **Windows Update support links from an endpoint were stored unchecked** and shown as clickable links; a compromised endpoint could plant a `javascript:` address (the CSP blocks it today, but it is cross-device data) | Only `http(s)` addresses are stored | `TestWebURLKeepsOnlyWebAddresses` |
| **Text cut in the middle of a character** at about a dozen places (job result messages, installer log texts, enrollment fields, session user agent, notification and report texts, security-event details): protobuf and PostgreSQL both refuse invalid UTF-8, so one unlucky installer message made a job result impossible to send. One helper had a half fix that kept the first byte of the cut character | One helper, `internal/shared/text.Truncate`, used everywhere | `internal/shared/text`, reproduced for the job result before the fix |
| **Deleting an agent release removed the file inside the database transaction**, before it was committed | The file is removed after the commit | `internal/server/agentrel` tests |
| **A stored installer could be a partial file after a crash**: the content store renames a file to its hash and trusts it afterwards, without syncing it first | The file is synced before it gets its final name | |
| The winget index reader (hand-written SQLite parser over network data, run in a background goroutine) had no fuzz target and no panic guard | A fuzz target (`FuzzParseDB`) and a guard that turns a panic into a refused index | 20,000 random mutations: no panic, none slower than 15 ms |
| Enrollment held its concurrency slot until the transaction returned normally | Released with `defer` | |

Not changed, and why: see the review report (`docs/CODE-REVIEW-D115.md`).

## 9m. Performance pass (D116 to D118): what it touches

No protocol, key, certificate or permission changed. These are the changes that sit near a security control, and the evidence for each.

| Change | Why it does not weaken a control | Evidence |
|---|---|---|
| **Job offers are verified on the receive path** instead of in the stream loop | The same `envelope.Verifier` runs, with the same replay ledger, and every rejection still sends a `SecurityEvent`. The only change is where it is called from. `offerMu` makes two offers (or an offer from the previous stream's receiver) run one after the other, so the ledger check and its record cannot interleave. Nothing the server sends other than a job offer is handled on the receive path | `TestRestartLatencyWhileHardwareIsCollected`, `TestRestartLatencyRightAfterTheAgentConnects`, the envelope tests under `-race` |
| **Restart requests run on their own loop** | The job is still verified, validated (`ValidateWU`), checked against the local policy ceiling (`reboot`) and persisted before it runs; only the loop that runs it differs. The restart plan is guarded by a mutex because both loops use it. A restart still waits for a job it would interrupt | `TestRestartIsNotHeldBackByARunningScan`, `TestRestartWaitsForARunningInstaller` |
| **A second restart request joins the running countdown** (agent) and **returns the unfinished restart job** (server) | The server request still needs `updates:write`, is rate limited like every API call and is audited each time (the second entry carries `joined_existing_job`). Windows' `ERROR_SHUTDOWN_IS_SCHEDULED` / `ERROR_SHUTDOWN_IN_PROGRESS` is the only error treated as "already on its way" | `TestRestartClickedTwiceIsOneJob`, `TestSecondRestartRequestDoesNotRestartTheComputerTwice` |
| **`CheckDeviceCert`** replaces two reads in the certificate check | The check still runs on every TLS handshake, every agent stream and every renewal, with no cache: the certificate must be known, not revoked, belong to the device named in it, and the device must be `active`. A device row that no longer exists now answers "unknown certificate" instead of "device is not active"; both refuse | `TestEndToEnd` (revoked device cannot open a stream), `TestCertificateRenewal` |
| **Smaller per-connection read buffer** | Message size limits (4 MiB), TLS 1.3 and the keepalive policy are untouched | `TestEndToEnd`, `TestAgentSelfUpdateEndToEnd` (content download over the stream) |
| **Retention of `software_history`** (setting, default 730 days) | Deletes inventory history only, per organization, in batches. The audit log and the installed-software table are never pruned. The run is itself an audit entry (`maintenance.retention`) | `TestPruneSoftwareHistoryBatchesAndKeepsRecentAndOtherOrganizations` |
| **`schtasks.exe` calls time out after a minute** | Same arguments and paths as before; only a time limit is added | compiled and vetted for Windows only |

Not changed on purpose: no cache for revocation, no new listener, no new secret. `govulncheck` could not run in the sandbox that produced this change (the vulnerability database host was blocked), so the dependency check still has to run in CI.

## 10. Vulnerability disclosure
Reports go through GitHub private vulnerability reporting (Security tab, "Report a vulnerability"); the full policy is in the
repository's [SECURITY.md](../SECURITY.md). LibrePatch has a single maintainer, so response times there are goals, not guarantees.
- Safe harbour for good-faith research on your own installations. Don't test against systems you do not own.
- Supported versions: the latest release and the one before it get security fixes.

## 9f. Phase 6: security review

A line-by-line review of the code against every row of section 5 and every claim in 9–9d (read-only; Windows-only code was read, not run). Where a row did not match the code, the row above was corrected instead of leaving the claim standing. Fuzz targets were added for the job envelope (with a valid signature and without), the enrollment string, the release manifest and bundle, the job-body validators and the uninstall-key scanner; `make fuzz` runs them all, together with the earlier ones.

### Fixed in Phase 6

| Finding | Fix |
|---|---|
| **The long-running server held a PostgreSQL superuser URL** (it needed it only for migrations): code execution in the server could rewrite the audit log and re-chain it, or run programs in the database container | Migrations, backup and restore run in a one-shot `maintenance` compose service that alone mounts the owner credential; the server mounts only the DML-only role and runs with `LIBREPATCH_MIGRATE_ON_START=false`. Fresh databases create a **non-superuser** `librepatch_owner` (the bootstrap superuser is used only by the init script). The compose test asserts the server has neither secret and that backup and `--verify` work through `maintenance`. Databases created earlier keep a superuser owner (PostgreSQL cannot demote the bootstrap role): RUNBOOK 6, "Hardening an older database" |
| `%ProgramData%\LibrePatch` could be pre-created by a standard user, who would stay its owner and could later rewrite the agent configuration (server, root pin, `allowed_jobs`) | Install creates the directory with the protected DACL in one step, refuses an existing one that is a reparse point or is not owned by SYSTEM or Administrators, and tells the administrator what to remove. (Windows code, compiled and vetted but not run) |
| Per-device rate limits covered only inventory and job updates; one device could flood the audit chain with security events and stall every audit-writing action | Heartbeats and hardware reports (30/min) and security events (6/min, excess acknowledged and not recorded) are limited per device |
| MFA failures counted once per five wrong codes toward the account lockout (about 50 guesses per lockout window) | Every wrong code counts; a locked account cannot continue an existing MFA-pending session |
| The last-administrator guard was check-then-act (two administrators could disable each other) | Serialized by a process-wide mutex around the three handlers that can remove an administrator |
| A site-limited approver could revoke another site's device by approving an enrollment that claimed (by hardware ID) to replace it | The approver must hold `devices:write` for the replaced device's site as well |
| Password reset, MFA reset and the user's own password change left API tokens (up to 365 days) alive | All three revoke the user's API tokens |
| msiexec switches in the `-x`/`--x` spelling bypassed the deny-list | The key is normalized before the lookup |
| Reserved device names stopped at COM3 and LPT3; trailing dots and spaces were not rejected in archive entries | COM1–9, LPT1–9, `CONIN$`, `CONOUT$` and trailing dots or spaces are refused |
| The vendor download client had no timeout at all (a silent server could stall the single job loop forever) | Header timeout, handshake timeout and a 2-minute stall limit between bytes |
| Deleting an agent release could delete a file that a custom package also uses | The file is deleted only when neither table references it |
| Documentation claimed CodeQL and Renovate | CodeQL (GitHub's default setup, switched on in the repository settings) and Dependabot (`dependabot.yml`) were added; the claims were corrected where the feature did not exist (T-WEB-7 prefix, T-LPE-3, T-LPE-9, T-WEB-2, T-DEV-5, T-SRV-4, T-SRV-2, T-SUP-2/3, T-ENR-1) |

### Residual risks and gaps (accepted for now, in order of concern)

| ID | Gap | Notes |
|---|---|---|
| R-1 | **No DACL check on uninstall executables** (T-LPE-3): an application installed with a user-writable folder under Program Files, or anything under `ProgramData\Package Cache`, can have its uninstaller replaced by a local user, and the next uninstall that LibrePatch performs for that application runs the replacement as SYSTEM | Needs a Windows implementation (owner and DACL of the file and each parent, open by handle). Mitigation until then: use `allowed_jobs` without `software_uninstall` on sensitive machines |
| R-2 | **No root-signed key revocation**: the field exists in the protocol but nothing produces or enforces it. A stolen job-signing key is valid until it is rotated out and, for an agent that was offline, until its certificate expires (2 years) | Planned: revocation statements signed by the root at unlock time; shorter job-signing certificate lifetimes |
| R-3 | A compromised server can still sign any typed job (section 6). The mitigations listed there (four-eyes approval, anomaly alerts, HSM-held signing key) are **not implemented** | Largest remaining design risk; the agent-side ceiling and vendor-signed agent updates bound it |
| R-4 | No scheduled audit-chain verification and no SIEM streaming | Verify from the console or `admin verify-audit`; copy `audit_log` out of band if you need an external record |
| R-5 | No step-up MFA for sensitive actions (large deployments, role changes, token creation) | Sessions are short (30 min idle) and tokens cannot manage users or mint tokens |
| R-6 | ~~API tokens and cached site scope on open SSE streams are not re-validated until the stream ends~~ **Closed in D115**: every open event stream re-checks its caller (session or API token, account status, role bindings) once a minute and ends when the caller is no longer allowed | `TestReauthenticateFollowsTokenUserAndRole` |
| R-7 | Unauthenticated connections to the gateway port are bounded only by the TLS handshake timeout and the operating system | Put a firewall or connection limit in front if the port is exposed to untrusted networks |
| R-8 | The compose file sets no CPU, memory or process limits | Set them to your host in a compose override |
| R-9 | Per-user (HKCU) MSI uninstalls through the helper may be refused because the helper requires the executable under the staging directory | Fails closed; to be confirmed on a real machine |
| R-10 | Audit verification (`POST /audit/verify`) reports the size of the global chain to any administrator | Single-organization installs only today |
