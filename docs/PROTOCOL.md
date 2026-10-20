# Agent ↔ Server Protocol (v1)

Status: **v1 implemented in Phase 1.** The normative source is `proto/librepatch/agent/v1/*.proto` (`buf lint` runs in CI). This document explains intent, ordering and validation rules that protobuf can't express.

**Phase 3 additions** (§5, §5.1–5.3, §8): job envelopes are issued (`SOFTWARE_INSTALL`, `SOFTWARE_UPDATE`, `SOFTWARE_UNINSTALL`, `INVENTORY_FULL`, `CANCEL`), the agent reports through `JobUpdate`, and uploaded installers are fetched with the `FetchContent` stream.

**Phase 1 scope:**
- Implemented: enrollment, approval polling, the `Connect` stream (Hello/HelloAck, Heartbeat, hardware inventory with Ack, SecurityEvent, GoAway), `RenewCertificate`, signing-certificate distribution, and agent-side envelope verification.
- Not yet: the server sends no `JobOffer` messages until Phase 3; software inventory deltas and `InventoryChunk` arrive in Phase 2; content download arrives in Phase 3.

**Message names in the `.proto` files:**

| This document | `.proto` |
|---|---|
| `Enrollment` | `EnrollmentService` |
| `AgentChannel` | `AgentChannelService` |
| `AgentMessage` | `ConnectRequest` |
| `ServerMessage` | `ConnectResponse` |

Both `EnrollResponse` and `EnrollStatusResponse` wrap a shared `EnrollResult`.

## 1. Transport
- **gRPC over HTTP/2 over TLS 1.3 only** (`MinVersion = MaxVersion = TLS13`). TLS 1.3 cipher suites aren't configurable in Go; all three are AEAD.
- Server port: **8443** by default, published directly from the server container. It's never terminated by Caddy or any other proxy.
- The agent supports an HTTPS `CONNECT` proxy (system WinHTTP setting or `config.json`). **A TLS-inspecting proxy breaks mTLS by design.** The customer must exempt the gateway host, and the RUNBOOK says so.
- The max message size is 4 MiB. Larger payloads (full inventory) are chunked.

## 2. Trust anchors and certificates

```
Root CA (ECDSA P-384, 20y)  — key encrypted with an owner passphrase; unlocked only for root operations
 ├── Issuing CA (P-384, 5y, pathlen 0, EKU serverAuth+clientAuth)   — key encrypted with server KEK
 │    ├── Gateway server cert (P-256, 90d, auto-renewed, SAN = configured gateway hostnames/IPs)
 │    └── Device client certs (P-256, 90d; CN = device UUID; URI SAN urn:librepatch:device:<uuid>; EKU clientAuth)
 └── Job-signing cert (Ed25519, 2y, EKU = 1.3.6.1.4.1.32473.7231.1.1 "current job signing" (placeholder PEN, see DECISIONS D25), issued *directly* by root)
```

- **The agent pins the root** by SPKI SHA-256 from its enrollment bundle. It accepts a job-signing certificate only if the root issued it directly and it has the job-signing EKU. The issuing CA can't produce one, because of its EKU constraint and path rule. So stealing the TLS issuing key does **not** let an attacker sign jobs.
- **The device key is generated on the device.** It uses CNG: `Microsoft Platform Crypto Provider` (TPM 2.0) when available, otherwise `Microsoft Software Key Storage Provider` with `NCRYPT_MACHINE_KEY_FLAG` and export disabled. It's exposed to Go's TLS stack as a `crypto.Signer`. The private key never exists in agent memory or on disk in plaintext.
- **Placeholder:** 32473 is IANA's documentation PEN (RFC 5612). It will be replaced by a registered PEN before release; agents will accept both during the transition.
- **Backdating:** every certificate's `NotBefore` is backdated by `pkix.CertBackdate` (5 min) to tolerate clock skew. The intended lifetime is `NotAfter − NotBefore − 5 min`, and agents use that for renewal decisions.

## 3. Enrollment bundle

The MSI or command line takes one opaque string:

```
LP1.<base64url(JSON)>
{"v":1,"gw":"agents.example.com:8443","root":"sha256/<b64 SPKI hash>","tok":"<32-byte random b64url>","org":"<uuid>"}
```

The token is shown to the admin once. The server stores only `SHA-256("librepatch/enroll-token/v1\0" || token)`, because the token is 256-bit random and a slow hash isn't needed. After the server accepts the enrollment (approved *or* pending), the agent erases the token from `config.json`.

**Install command:** `librepatch-agent.exe install --server host:port --token LP1....`. `--server` overrides the gateway address inside the bundle; the root pin always comes from the bundle.

## 4. RPCs

```proto
service Enrollment {                        // TLS required, client cert NOT required
  rpc Enroll(EnrollRequest) returns (EnrollResponse);
  rpc EnrollStatus(EnrollStatusRequest) returns (EnrollResponse); // only while pending approval
}
service AgentChannel {                      // client cert REQUIRED (interceptor + VerifyConnection)
  rpc Connect(stream AgentMessage) returns (stream ServerMessage);
  rpc RenewCertificate(RenewRequest) returns (RenewResponse); // also allowed with an expired-but-in-grace cert
}
// Content: HTTPS GET on the same listener, mTLS required (see §8)
```

The listener uses `tls.VerifyClientCertIfGiven`. A gRPC interceptor allows the two `Enrollment` methods without a certificate and **rejects every other method unless a verified, active, non-revoked device certificate is present**.

### 4.1 Enroll
```
EnrollRequest  { token, csr_der (P-256), hostname, smbios_uuid, serial, os_build, arch, agent_version }
EnrollResponse { status [APPROVED|PENDING|REJECTED], device_id, ticket (if pending),
                 client_cert_der, issuing_ca_der, job_signing_certs_der[], retry_after_s }
```
**The server checks:**

- the token hash exists, isn't expired or revoked, and `used_count < max_uses` (incremented in the same transaction);
- the CSR is well-formed and self-signed with a P-256 key;
- rate limits: per source IP 10/min and per token 60/min by default (burst equal). `LIBREPATCH_ENROLL_RATE_PER_IP` and `LIBREPATCH_ENROLL_RATE_PER_TOKEN` change them; raise them only for a rollout of many machines behind one NAT address, or enrolling 1,000 devices from one address takes 100 minutes (see LOADTEST.md).

Failures return one generic error. The detailed reason goes to the audit log only.

**Duplicate devices.** If `smbios_uuid`+`serial` matches an active device, the request becomes a **re-enrollment** that needs approval, regardless of the token setting. This stops one token from silently taking over an existing device's identity.

**Pending approval.** `EnrollStatus(ticket)` is called at the server-suggested interval (`retry_after_s`; 60 s by default, configurable with `LIBREPATCH_ENROLL_POLL_INTERVAL`) plus up to 1/3 jitter. This is the only polling in the protocol, and it only happens while pending. The ticket is stored hashed; when the device is approved, the next poll returns the client certificate and the ticket is invalidated.

### 4.2 Connect: stream messages
```
AgentMessage (oneof):
  Hello          { device_id, agent_version, boot_id, capabilities[], revs{software,hardware,users,wu},
                   outbox_pending, cert_not_after, local_policy_hash }
  Heartbeat      { uptime_s, pending_reboot, sessions[], free_disk_system }   // every 5 min, only if changed or 30 min elapsed
  JobAck         { job_id, attempt, state [ACCEPTED|REJECTED], reject_reason }
  JobProgress    { job_id, attempt, phase, percent, message }                 // throttled ≤ 1/5 s
  JobResult      { seq, job_id, attempt, outcome, exit_code, reboot_required, detection, log_tail ≤ 64 KiB,
                   started_at, finished_at }
  InventoryDelta { seq, section, base_rev, new_rev, upserts[], removes[] }
  InventoryChunk { seq, section, new_rev, index, total, items[] }
  SecurityEvent  { seq, kind [BAD_SIGNATURE|WRONG_DEVICE|REPLAY|EXPIRED|POLICY_CEILING|HASH_MISMATCH|SIGNER_MISMATCH], detail }

ServerMessage (oneof):
  HelloAck       { server_time, job_signing_certs[], signing_key_revocations[] (root-signed; defined, NOT yet produced or enforced, see SECURITY 9f R-2),
                   resync_sections[], config (SignedEnvelope) }
  JobOffer       { envelope: SignedEnvelope }
  JobCancel      { envelope: SignedEnvelope }      // cancel is itself a signed job of type CANCEL
  Ack            { seq }                            // agent may delete outbox entries ≤ seq for that stream
  ResyncRequest  { section }
  GoAway         { retry_after_s, reason }
```

**Delivery semantics:**

- **Agent to server is at-least-once.** Every result, delta and event carries a monotonically increasing per-agent `seq`, persisted in the bbolt outbox. The server processes it idempotently, keyed by `(device_id, seq)` for deltas and `(job_id, attempt)` for results, then sends `Ack{seq}`.
- **A job offer is acted on when it arrives.** The agent reads the stream from the moment `HelloAck` has been handled, and verifies and accepts a `JobOffer` on the receive path, before (and while) it sends its first hardware and software reports. Other server messages are queued for the agent's loop. This is an agent-internal change; nothing on the wire differs, so older and newer agents and servers work together (D116).
- **Server to agent:** a job stays `sent` until `JobAck`. On every `Hello`, the server re-offers all jobs for the device that are `sent`, not acked and not expired. The agent's ledger makes duplicate offers harmless.

## 5. Signed job envelope

```proto
message SignedEnvelope {
  bytes  payload   = 1;  // serialized JobEnvelope; signature covers exactly these bytes
  bytes  signature = 2;  // Ed25519( "librepatch/job/v1\x00" || payload )
  bytes  key_id    = 3;  // SHA-256 of signing cert SPKI
}
message JobEnvelope {
  uint32 version = 1;               // 1
  string job_id = 2;                // UUIDv7
  string org_id = 3;
  string device_id = 4;
  string target_user_sid = 5;       // "" = machine scope
  int64  issued_at = 6; int64 not_before = 7; int64 expires_at = 8;   // unix seconds
  bytes  nonce = 9;                 // 16 random bytes
  uint32 attempt = 10;
  string deployment_id = 11;
  MaintenanceWindow window = 12;    // optional; evaluated on device
  JobType type = 13;
  oneof body {
    InstallBody install = 20; UninstallBody uninstall = 21; WuScanBody wu_scan = 22;
    WuInstallBody wu_install = 23; WuHideBody wu_hide = 24; RebootBody reboot = 25;
    InventoryBody inventory = 26; AgentUpdateBody agent_update = 27; CancelBody cancel = 28;
    WakeBody wake = 29; InspectBody inspect = 30;   // D125
    ConfigBody config = 31;   // reserved, not implemented (29 and 30 are taken by wake and inspect)
  }
}
```

The agent verifies the signature over the raw bytes **before** parsing them. That removes any canonical-encoding ambiguity. The domain-separation prefix stops a signature made for a different purpose (for example a license document) from being reused as a job.

**Agent verification order.** A failure at any step rejects the job and emits a `SecurityEvent`.

1. `key_id` maps to a known job-signing certificate that chains directly to the pinned root, has the job-signing EKU, is in its validity period, and (once revocation statements are implemented, SECURITY 9f R-2) isn't on the root-signed revocation list. Today a compromised job-signing key is retired by rotating it on the server: agents replace their stored signing certificates at the next connection, and the old certificate expires on its own.
2. The Ed25519 signature is valid.
3. The payload parses, `version` is supported, and `type` matches the `body` case.
4. `device_id` and `org_id` match this agent's certificate identity.
5. `issued_at − 5 min ≤ now ≤ expires_at`. Also `expires_at − issued_at ≤ 30 days`; this cap is enforced by the agent so the replay ledger stays bounded.
6. `job_id` isn't in the executed/accepted ledger. Entries are kept until `expires_at + 24 h`.
7. `type` is allowed by the **local policy ceiling**: set at install time through an MSI property, stored in the ACL-protected `config.json`, and impossible for the server to raise.
8. Body validation: schema, allow-listed argument tokens, SHA-256 present for every installer, scope consistent with `target_user_sid`.

**Clock.** The agent records `server_time − local_time` from `HelloAck` and uses the adjusted clock for checks while that offset is fresh (under 24 h). The raw clock is used offline. If the skew exceeds 5 min, the agent reports it as a health warning.

**Signing-key rotation.**

1. The admin unlocks the root.
2. The server issues a new job-signing certificate.
3. `HelloAck` delivers it.
4. The agent accepts both certificates until the old one expires or is revoked.

**Revocation** statements are signed by the **root** (`"librepatch/revoke/v1\x00" || key_id || revoked_at`). A stolen job-signing key can therefore never be used to sign itself back into validity.

### 5.1 Install body (as built)

The authoritative definition is `InstallBody` in `envelope.proto`. In short:

```
InstallBody {
  package_id, name, version            // informational; shown in logs
  scope [MACHINE|USER]                 // must agree with target_user_sid
  installer { type, nested_type, nested_path, sha256 (required), size, file_name,
              sources[] (server content and/or vendor URL), args[] (validated tokens only),
              success_codes[], expected_codes[], signer_pin? { subject, thumbprint_sha256[] } }
  detection[] { kind [MSI|REGISTRY|FILE|APPX], key, value_name, version, cmp [EQ|GE] }
  preconditions { min_free_mb, os_build_min }
  timeout_s, max_retries, retry_backoff_s
  reboot [NEVER]                       // reboot-required is reported, never performed
  allow_downgrade, update              // update = SOFTWARE_UPDATE of an existing install
  prompts? { in_use [IGNORE|SKIP|ASK|CLOSE], processes[] (image names, validated),
             ask_timeout_s, defer_minutes,
             restart [NONE|ASK|COUNTDOWN], restart_notify_minutes }   // optional messages to the signed-in user (D124)
}
```

- The server builds `args` from the manifest or override switches after validating each token (`internal/shared/installer`). The agent validates them again; an argument containing shell metacharacters, a path traversal or a control character rejects the job.
- A detection rule is evaluated before the run (already satisfied: success, nothing executed) and after it (a success exit code with a failed detection is `failed_detection`).
- File detection paths may contain only allow-listed environment variables (`%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramW6432%`, `%CommonProgramFiles%`, `%ProgramData%`, `%SystemRoot%`, `%WinDir%`, and for user scope `%LOCALAPPDATA%`, `%APPDATA%`, `%USERPROFILE%`) and never `..`.

### 5.2 Uninstall body

```
UninstallBody {
  package_id, name, scope, item_source [reg64|reg32|hku|hku32|msi], item_key,
  product_code?, method [AUTO|PRODUCT_CODE], extra_args[] (validated), timeout_s, max_retries, retry_backoff_s
}
```

It names an inventory row. **The server never sends a command line**: the agent re-reads that row's `Uninstall` registry data itself and derives the command (design §7.5).

`remove_older_than` (cleanup of an outdated copy, set by update deployments): the agent removes the row only if its `DisplayVersion` is strictly older than this version, treats a row that is already gone as success, and leaves an equal, newer or unparseable version alone. An empty value is an unconditional uninstall.

`INVENTORY_FULL` (`InventoryBody`) is the **refresh** job: it triggers an immediate software/users sync, a hardware report if the hardware changed, and a heartbeat.

### 5.2a Windows Update bodies (Phase 4)

```
WuScanBody    { service [DEFAULT|WINDOWS_UPDATE|MICROSOFT_UPDATE], include_drivers }
WuInstallBody { service, include_drivers, updates[{update_id uuid, revision}] (1..200), reboot RebootPolicy,
                timeout_s, max_retries, retry_backoff_s }
WuHideBody    { service, updates[], hide bool }
RebootBody    { reboot RebootPolicy, reason (plain text, bounded) }
RebootPolicy  { allow [NEVER|OUTSIDE_ACTIVE_HOURS|DEADLINE|NOW], active_hours{start_minute,end_minute},
                deadline_at, notify_minutes 1..1440 }
```

- **Updates are named by identity, never by title.** The agent runs a fresh WUA search and installs exactly the listed `(update_id, revision)` pairs it finds; a pair it cannot find is reported as a per-update failure, and nothing outside the list is touched. `WU_*` jobs are machine-scope only; the agent's policy ceiling names them (`wu_scan`, `wu_install`, `wu_hide`, `reboot`).
- **`RebootAllow`.** `NEVER` only reports. `OUTSIDE_ACTIVE_HOURS` and `DEADLINE` are stored as a persisted plan that the agent re-checks every tick; a restart never starts inside the active hours (a `DEADLINE` plan restarts at the deadline at the latest) and always gives signed-in users `notify_minutes` of system countdown. `NOW` is accepted only in `RebootBody` (a `WU_INSTALL` that asks for it is rejected by validation) and needs at least one minute of countdown.
- **Result.** `JobResult.wu_results` has one `WuUpdateResult{update_id, revision, result [INSTALLED|INSTALLED_REBOOT|FAILED|NOT_APPLICABLE|DOWNLOAD_FAILED], hresult}` per requested update. The job outcome is `REBOOT_REQUIRED` when any update needs a restart, `RETRYABLE` for transient WUA errors (retried with the job's backoff inside its expiry) and `FAILED` when none was installed. `NOT_APPLICABLE` (the scan no longer offers it) counts as done.
- **Window.** The optional `MaintenanceWindow` of the envelope applies to WU jobs exactly as to installs (device-local time unless `tz` is set).

### 5.2b The `WU` inventory section

`InventoryReport{section=WU}` is always a **full replacement** (`WuInventory{ scanned_at, scan_error, reboot_required, truncated, service, policy WuPolicyInfo, updates[] }`) as one message of at most 1,000 updates (the agent sets `truncated` beyond that and the server rejects more). Only updates that are missing, downloaded, hidden, pending a restart or failed are listed; installed updates are never reported. The agent bumps a generation counter whenever the snapshot changes (a new scan result, a reboot-state change, a policy change); the server stores the last generation it applied (`devices.wu_rev`), the agent advertises its own in `Hello.revs["wu"]`, and a mismatch makes the server ask for `ResyncRequest{WU}` (`HelloAck.resync_sections`). `WuPolicyInfo` reports WSUS (`UseWUServer`, server URL), Windows Update for Business deferrals, "configure automatic updates" options, a disabled Windows Update service and notes.

### 5.2c Agent update body (Phase 5)

```
AgentUpdateBody { manifest bytes, signature bytes (64), key_id bytes, timeout_s }
Manifest (JSON, the exact signed bytes) { format 1, product "librepatch-agent", version, os, arch, sha256 (hex), size,
  released_at?, min_version?, rollback_from[]?, authenticode_subject?, notes? }
Signature = Ed25519( "librepatch/release/v1\0" || manifest )   -- by a VENDOR release key
```

- **Two signatures, two jobs.** The customer server signs the *job* like any other. The *release* is trusted only because its manifest verifies under a vendor release public key **compiled into the agent** (`-ldflags -X .../internal/shared/release.PublicKeysHex=<hex>[,<hex>]`; a build without one rejects every update). A compromised server can pick *when* an agent updates and *which vendor release*, never supply its own binary.
- **Agent checks, in order:** manifest signature and strict parse (unknown fields, trailing data, bad hash/size/version are refused) → `os`/`arch` match → version rules (`CheckApplicable`: not the running version; not older unless the current version is listed in `rollback_from`; not below `min_version`) → no other update in flight → download over the mTLS channel (`FetchContent`, authorized for a job whose manifest names that SHA-256) → size and SHA-256 while streaming, re-hash from a locked handle → Authenticode subject equals `authenticode_subject` when set (release builds require it: `RequireAuthenticode`) → the binary run with `version` must print `librepatch-agent <version> (`.
- **Switch (ARCHITECTURE §10):** write the binary to the inactive slot, persist `update.json`, arm the rollback task (abort if that fails), point the service at the new slot, ask the service manager to restart. The job stays `running` (`restarting_into_<version>`) and **ends after the restart**: `succeeded` when the new process completes its first handshake, `failed` ("did not become healthy…") when the safety net restored the old slot.
- **Server side:** job type `agent_update` in `jobs.type`; per-device/release attempts in `agent_attempts`; `FetchContent` authorizes the binary when the live job's manifest names that hash.

### 5.3 Job reporting

```
JobUpdate { job_id, attempt, state (JobState), reason, result? (JobResult) }
JobResult { outcome [SUCCESS|REBOOT_REQUIRED|RETRYABLE|FAILED], exit_code, detection_passed,
            installed_version, message, log_tail (≤ 16 KiB), started_at, finished_at, already_satisfied }
```

- `JobUpdate` travels through the agent's durable outbox with the same `seq`/`Ack{seq}` mechanism as inventory, so a result survives a dropped stream or a restart and is delivered at least once. The server applies updates idempotently and ignores updates for a job that is already terminal.
- The agent states are `ACCEPTED, WAITING, RUNNING, SUCCEEDED, SUCCEEDED_REBOOT, FAILED, EXPIRED, CANCELLED, REJECTED`; the server stores them as `accepted/waiting/running/succeeded/succeeded_reboot/failed/expired/cancelled/rejected` (plus `queued` and `sent` before the agent has acknowledged), with `status_reason` carrying the cause, for example `waiting_user_logon`, `retry_backoff`, `failed_detection`.
- **Offer, re-offer and ack.** `JobOffer{signed}` is sent when a device connects (for every job that is `queued` or `sent`, not expired and with its dependency met) and at creation time to online devices. Until the server sees an update for the job it is offered again with a **fresh nonce** on the next connect. The agent recognizes a job ID it already holds and acknowledges instead of treating it as a replay (a genuinely replayed envelope for a job it does not hold is still rejected).
- **Cancel.** Cancelling a job that the agent may already hold sets `cancel_pending` and issues a signed `CancelBody` job for it; the agent stops the process tree if the job is running and reports `CANCELLED`.
- **Server-side limits.** Updates from a device are accepted only for that device's own jobs (`WHERE device_id = $cert_device`); unknown job IDs are ignored; result text is length-capped and stored as data, never interpreted.

## 6. Inventory deltas

Sections: `HARDWARE`, `USERS`, `SOFTWARE` and `WU` (§5.2b). Each section has its own revision counter, kept by the agent and by the server (`devices.hardware_rev`, `users_rev`, `software_rev`).

**Item key.** A software item is identified by the tuple `(source, scope, user_sid, item_key)`: `source` is `reg64`, `reg32`, `hku`, `hku32`, `msi`, `appx` or `portable`; `scope` is `machine` or `user`; `user_sid` is empty for machine scope. `item_key` is the Uninstall subkey name, MSI ProductCode, AppX package full name or portable directory.

**What the agent stores.** Only the *acknowledged snapshot*: a map of `item key bytes → sha256(item)` plus the acknowledged revision, in its bbolt state file. That is a few hundred KB even for thousands of items, and it never holds a second full copy of the data. The persisted state advances **only when the server's `Ack{seq}` arrives**.

**Delta.** `SoftwareDelta{base_rev, upserts, removes}` travels in `InventoryReport{section=SOFTWARE, rev = base_rev + 1}`. The server applies it only if `devices.software_rev == base_rev`, in one transaction that also writes history, and then acknowledges. On any other value it applies nothing, sends `ResyncRequest{SOFTWARE}` and does not acknowledge; the agent drops the unacknowledged report and sends a full snapshot.

**Full snapshot.** `SoftwareChunk{index, total, items}` messages (250 items each, in order, one revision) are staged per connection and applied atomically on the last chunk; items missing from the snapshot are removed. The server checks `index` is sequential, `total ≤ 400`, the revision is constant and the running total ≤ 25,000 items. A dropped stream discards a half-received snapshot.

**When a full snapshot is sent:** first report, `ResyncRequest`, a Hello whose revisions differ from the server's (`HelloAck.resync_sections`: restored backup, wiped agent state, lost acknowledgement), or a delta of more than 5,000 changes.

**Partial scans are never read as removals.** If one group of sources fails (for example an offline user hive that is locked), the agent keeps the previous items of that group in its snapshot instead of reporting them removed.

**Triggers.** Registry change notifications on the Uninstall keys, AppX store, ProfileList and loaded user hives are debounced (30 s quiet period) and trigger a rescan at background priority; a full reconcile runs daily (±jitter) and on resync. The `USERS` section is a small full snapshot, re-sent when its fingerprint changes.

**Limits (server side, SECURITY T-DEV-2/3):** 25,000 software rows and 500 users per device, 10,000 changes per delta, string fields 512 B–2 KiB, install dates `YYYY-MM-DD`, user SIDs well-formed, NUL bytes stripped, per-device inventory message rate limit (burst 450, 120/min). The agent caps at 25,000 items and sets `truncated`; the device is then flagged `inventory_truncated` and the console says so. Invalid data ends the stream with `InvalidArgument` and a `gateway.protocol_violation` audit entry.

**History.** The first snapshot of a device is a baseline and creates no history. Later installs, removals and version changes are recorded in `software_history`.

## 7. Liveness and reconnect
- Transport: gRPC keepalive every 90 s with a 20 s timeout. The server's enforcement policy allows a minimum of 60 s.
- Online means a live stream (tracked in the server hub). `last_seen_at` is written on connect, on disconnect and on each heartbeat; heartbeats are sent only when something changed, or every 30 min, so idle agents cost almost nothing.
- Reconnect uses exponential backoff with **full jitter**: `sleep = rand(0, min(300 s, 1 s × 2^n))`. The counter resets after 10 min of a healthy stream. After a server-initiated close (`GoAway` or shutdown), the agent waits `retry_after` plus a random 0 to 30 s to avoid a reconnect stampede.
- **Revocation is immediate:**
  1. The admin revokes the device.
  2. The device row is set to `revoked` and its certificate serials are marked revoked.
  3. The hub sends `GoAway` and closes the stream at once.
  4. Revocation is enforced at three points: **every TLS handshake** (`VerifyConnection` looks up the certificate and device state in the database, with no cache), **every new gRPC stream or call** (so an already-open HTTP/2 connection cannot be reused), and the live stream itself, which the hub ends with `GoAway{reason:"revoked"}`. An agent that receives `revoked` marks itself rejected and stops reconnecting.
- **Certificate renewal.**
  - The agent renews when less than 1/3 of the lifetime (excluding the backdate) remains, measured on **server-corrected time**. It checks on a timer of lifetime/10, clamped to 1 s–1 h. `HelloAck.renew_certificate` also triggers renewal.
  - The agent sends `RenewCertificate` with a CSR from a **new** key (CNG name `LibrePatch-Agent-Device-<generation>`), stores the new certificate, deletes the old key, and reconnects.
  - When the device first connects with the new certificate, the server revokes the older ones (`revoke_reason='superseded'`).
  - An expired certificate can still call `RenewCertificate`, and only that RPC, for up to 180 days (`LIBREPATCH_DEVICE_RENEW_GRACE`) if the device is active. After that the device must re-enroll.
  - Renewals are rate-limited to 5 per device per hour.

## 8. Content download
- **Transport (D42):** the `FetchContent(FetchContentRequest{sha256, job_id, offset}) → stream FetchContentResponse{data, total_size}` RPC on the same mTLS channel. There is no separate HTTP endpoint. Chunks are 256 KiB; `offset` resumes an interrupted download.
- **Authorization:** content is served only if the calling device has a live (non-terminal, non-expired) job `job_id` whose envelope references exactly that SHA-256, and the blob exists for the device's organization. Devices cannot enumerate or download anything else. At most a few concurrent downloads per device are allowed (`fetchLimiter`).
- **Who serves what:** only **uploaded (custom)** installers come from the server. Winget installers are fetched by the agent straight from the vendor URL over HTTPS with the system trust store.
- The integrity guarantee is always the SHA-256 in the signed envelope, never the transport: the agent hashes while streaming, then re-opens the staged file locked and hashes it again before running it.

## 9. Service ↔ helper IPC (local only)
- **Transport (as built):** two anonymous pipes created by the service, one for the task and one for the result. Only the helper's two ends are inherited (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`), and their numeric handle values are passed on the helper's command line (`librepatch-agent.exe helper <taskHandle> <resultHandle>`). There is no named pipe and no listening endpoint. The helper process is created suspended in a kill-on-close Job Object with the user's primary token (`WTSQueryUserToken`, never the linked elevated token).
- **Framing:** one JSON `HelperTask` (≤ 1 MiB) in, one JSON `HelperResult` (≤ 64 KiB) out. The helper takes exactly one task and exits.
- **`HelperTask`:** the `SignedEnvelope` bytes, the pinned root and signing certificates (DER), device and org IDs, the server-corrected time, the target SID, the staging directory, the staged file (install jobs), and the already-built command (`exe`, `args`, working directory, log path, timeout).
- **The helper re-verifies** the envelope signature and chain, device and org, expiry (§5 steps 1 to 5), that `target_user_sid` equals the SID of its own token, that every path it is given lies under its staging directory (`%ProgramData%\LibrePatchStage\<SID>`), and the SHA-256 of the staged file, before it starts the command in its own Job Object.
- **`HelperResult`:** `exit_code`, `timed_out`, `log_tail`, `error`. The service treats every field as untrusted data and performs post-detection itself.

## 10. Versioning
- Package `librepatch.agent.v1`. Changes within v1 only add fields or messages. `Hello.capabilities` advertises optional features, such as `wu`, `userctx` and `appx`.
- The server supports the current and previous agent minor versions at the same time. A breaking change becomes a `v2` service on the same listener.
