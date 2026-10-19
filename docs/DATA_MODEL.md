# Data model (PostgreSQL)

Status: Phase 1 tables are implemented in `db/migrations/00001_foundations.sql` (Phase 2 in `00002_inventory.sql`, Phase 3 in `00003_deployments.sql`): tenancy, identity, sessions, PKI, enrollment, devices, device certs and audit. Later sections are design. Column lists are abridged.

Phase 1 differences from the design below:
- `pki_material` stores the **root key sealed with the owner passphrase** (`key_protection='passphrase'`; argon2id + AES-GCM), so the server can unlock it only when the owner types the passphrase. The issuing, job-signing and gateway keys are sealed with the KEK.
- `sessions.pending_totp_enc` holds the new TOTP secret during a forced MFA re-enrollment. `setup_state` holds the first-run TOTP secret until setup commits.
- Device hardware is stored as a `jsonb` snapshot (`devices.hardware`, protobuf field names) plus denormalized columns for listing. The normalized software tables arrive in Phase 2.
- `device_certs.serial` is lowercase hex text.

## Conventions
- Primary keys are `uuid` (v7, so they sort by time). The audit log and event tables use `bigint` identity.
- **Every tenant-owned row has `org_id`**, and most also have `site_id`. v1 ships single-tenant (one org created at setup), but every query is scoped by org, and RBAC checks site scope.
- Every query is a sqlc-generated parameterized statement. The application never builds SQL by concatenating strings. The only dynamic SQL is the dynamic-group compiler, and it emits identifiers from a fixed allow-list, with all values as parameters.
- Timestamps are `timestamptz`.
- Migrations are forward-only and follow expand-then-contract across releases. `goose` runs them in transactions under an advisory lock.
- **Database roles:**
  - `librepatch_migrator`: owns the DDL;
  - `librepatch_app`: DML only, and on `audit_log` `INSERT`/`SELECT` only;
  - `librepatch_readonly`: reporting and backups.

## Tenancy and identity
```
organizations(id, name, created_at)
sites(id, org_id, name, timezone)
users(id, org_id, email citext unique, display_name, password_hash, status[active|disabled],
      failed_logins, locked_until, password_changed_at, created_at)
user_identities(id, user_id, provider[local|oidc:<name>], subject, unique(provider, subject))   -- OIDC-ready
mfa_totp(user_id, secret_enc bytea, confirmed_at)                     -- encrypted with server KEK
mfa_webauthn(id, user_id, credential_id, public_key, sign_count, aaguid, name, created_at)
mfa_recovery_codes(user_id, code_hash, used_at)
role_bindings(id, user_id, role[admin|operator|readonly], scope_type[org|site], scope_id)
sessions(id_hash bytea pk, user_id, created_at, last_seen_at, idle_expires_at, abs_expires_at,
         mfa_verified_at, ip, user_agent, csrf_secret)
api_tokens(id, org_id, name, token_hash bytea, scopes text[], site_ids uuid[], created_by,
           expires_at, last_used_at, revoked_at)
```

## Devices and PKI
```
enrollment_tokens(id, org_id, site_id, token_hash, max_uses, used_count, expires_at,
                  require_approval bool, default_group_ids uuid[], created_by, revoked_at)
devices(id, org_id, site_id, status[pending|active|revoked|retired], hostname, fqdn, domain,
        os_caption, os_build, os_ubr, arch, serial, manufacturer, model, chassis,
        cpu, ram_bytes, uptime_s, pending_reboot, system_drive_free_bytes, bitlocker jsonb, last_user, ips inet[],
        agent_version, enrolled_at, approved_by, last_seen_at, online bool,
        inventory_rev bigint, hw_rev bigint, local_policy jsonb)
device_certs(serial numeric pk, device_id, public_key_sha256, not_before, not_after,
             revoked_at, revoke_reason)
device_users(device_id, sid, username, domain, profile_path, last_logon_at, loaded bool,
             is_admin bool, primary key(device_id, sid))
device_sessions(device_id, session_id, sid, state, kind[console|rdp], updated_at)
pki_material(id, kind[root|issuing|job_signing], cert_der, key_enc bytea null, not_after, retired_at)
   -- root key_enc is NULL (offline). job_signing/issuing keys encrypted with server KEK.
```

## Inventory
```
software_titles(id, org_id, normalized_name, normalized_publisher, display_name, display_publisher,
                unique(org_id, normalized_name, normalized_publisher))
software_installs(device_id, source, scope[machine|user], user_sid ('' for machine), item_key,
                  title_id, name, version, version_key bytea null, publisher, install_date,
                  install_location, uninstall_string, quiet_uninstall_string, product_code,
                  system_component bool, first_seen_at, last_seen_at,
                  primary key(device_id, source, scope, user_sid, item_key))
                  -- indexes: (device_id), (title_id, version_key), and (title_id, device_id) INCLUDE (version)
                  --          WHERE NOT system_component (migration 00021: serves the Software page's counts)
software_history(id bigint, device_id, title_id, name, scope, user_sid, change[added|removed|version],
                 old_version, new_version, observed_at)
device_users(device_id, sid, username, domain, profile_path, last_logon_at, loaded, is_admin)
devices += software_rev, users_rev, software_updated_at, software_count, inventory_truncated,
           chassis, manufacturer, model, ram_bytes, os_build_num   -- last five are generated columns
                                                                       over the hardware JSON
```
- `version_key` is a byte-comparable encoding of the version (`internal/shared/vercmp`), so `version_key < $1` is correct in SQL, for example for "Chrome < 130". Unparseable versions have a NULL key and never match a version condition.
- **Title normalization** (`internal/server/inventory/normalize.go`): lower case, trademark marks, the version, architecture tokens ("(x64)", "64-bit") and per-user qualifiers removed; publisher legal suffixes ("Inc.", "GmbH") dropped. "7-Zip 23.01 (x64 edition)" and "7-Zip 24.08" are one title. Display names keep the original capitalization.
- Indexes: `(title_id, version_key)`, `(device_id)`, `software_titles (org_id, normalized_name text_pattern_ops)`. Search uses `strpos` (no LIKE escaping); a trigram index is deferred until 10k-device load tests (Phase 6).
- `software_history` is a plain table in Phase 2. Monthly partitioning and retention arrive with the load tests (Phase 6).

## Groups
```
groups(id, org_id, name, description, filter jsonb, created_by, created_at, updated_at, unique(org_id, name))
```
Phase 2 implements **dynamic groups only**; membership is computed on demand (nothing is cached or stored). Static groups and per-site scoping arrive with the deployment targets in Phase 3. Only `active` devices are ever members.

`filter` is a typed tree, parsed strictly and compiled to parameterized SQL by `internal/server/groups`:
```
{"op":"and","children":[
  {"op":"device","field":"chassis","cmp":"in","value":["laptop","notebook","portable"]},
  {"op":"software","title":"chrome","match":"contains","version":{"cmp":"lt","value":"130"}}]}
```
- Nodes: `and`/`or` (≥ 1 child), `not` (exactly 1), `device` (`field`, `cmp`, `value`), `software` (`title` + optional `match` exact/prefix/contains, `publisher`, `scope`, `version{cmp,value}`). All conditions of a `software` node must hold on the **same install row**. "Not installed" is `not` around `software`.
- Device fields (allow-list, each with its own comparators and value type): `hostname`, `os_caption`, `arch`, `agent_version`, `manufacturer`, `model`, `chassis`, `os_build`, `ram_bytes`, `online`, `pending_reboot`, `site_id`, and `disk_bitlocker` (any disk in a BitLocker state).
- Limits: depth 6, 50 nodes, 100 values in an `in` list, 200 bytes per value, 32 KiB per filter. Evaluation runs read-only with a 10 s statement timeout.

## Catalog
**Phase 3 as built** (`00003_deployments.sql`; the design below was trimmed to what exists):
- `groups.kind` (`dynamic` | `static`), `groups.filter` nullable for static groups, and `group_members(group_id, device_id)`.
- `catalog_packages(id, org_id, source[winget|custom], identifier, name, publisher, homepage, license, description, verified, self_updating, imported_at, imported_by)`, unique on `(org_id, source, identifier)`. There is no global (null-org) catalog; each organization imports its own.
- `catalog_versions(id, package_id, version, version_key, manifest_sha256)` and `catalog_installers(id, version_id, architecture, scope, installer_type, nested_type, nested_path, url, sha256, size, file_name, signer_subject, product_code, upgrade_code, switches, success_codes, expected_codes, min_os, detection, uses_content_blob, unsupported)`. Detection rules live in `catalog_installers.detection` (jsonb), not a separate table; `unsupported` explains why an installer cannot be deployed.
- `package_overrides(org_id, package_id, silent_args, extra_detection, pin, excluded, user_scope_policy, self_update_policy, updated_by, updated_at)`, `org_settings(org_id, user_scope_policy)`, `content_blobs(org_id, sha256, size, file_name, uploaded_by)` (bytes live on the content volume under `<LIBREPATCH_CONTENT_DIR>/<org>/<sha256>`).
- The winget index table is not built (D41). The `verified` flag is set at import from the shipped `matrix_results.json` (empty for now) and the `self_updating` mark from the shipped overlay.

Design (original sketch):
```
catalog_packages(id, org_id null(global), source[winget|custom|overlay], package_identifier,
                 name, publisher, homepage, license, verified bool, verified_matrix_run_id,
                 self_updating bool, imported_at, unique(org_id, source, package_identifier))
catalog_versions(id, package_id, version, version_key, manifest jsonb, manifest_sha256, imported_at)
catalog_installers(id, version_id, architecture, scope[machine|user|any], installer_type,
                   nested_type, url, sha256, size, signer_subject, signer_thumbprint_pin,
                   product_code, upgrade_code, switches jsonb, success_codes int[],
                   expected_codes jsonb, min_os, dependencies jsonb, elevation_requirement)
detection_rules(id, package_id, version_id null, scope, kind[msi|registry|file|appx], params jsonb)
package_overrides(org_id, package_id, silent_args jsonb, extra_detection jsonb, pin text,
                  excluded bool, user_scope_policy, self_update_policy, updated_by, updated_at)
content_blobs(sha256 pk, size, media_type, storage_path, origin[upload|cache], uploaded_by, created_at)
winget_index(package_identifier, name, publisher, latest_version, tags, moniker, synced_at) -- search only
```

## Deployments and jobs
**Phase 3 as built:**
- `deployments(id, org_id, name, action[install|update|uninstall], package_id, version_id, scope[machine|user], target_group_ids, target_device_ids, starts_at, expires_at, maint_window jsonb, unverified_confirmed, status[active|paused|completed|cancelled], created_by, created_at)`. The maintenance window is stored on the deployment and signed into each job; rings are Phase 4.
- `jobs(id, org_id, deployment_id, device_id, user_sid, type[software_install|software_uninstall|software_update|inventory_full], title, body bytea (unsigned envelope), depends_on, not_before, expires_at, attempt, status, status_reason, envelope bytea (last signed offer), created_at, sent_at, acked_at, started_at, finished_at, exit_code, detection_passed, reboot_required, cancel_pending, result jsonb)`. Indexes `(device_id, status)`, `(deployment_id, status)`, `depends_on`. A retry creates a new row with `attempt + 1`.
- `jobs.depends_when` (`success` default | `finished`, migration `00004`): a dependent job normally waits for its parent to succeed; `finished` releases it when the parent ends in any way except cancellation (used by update cleanup chains).
- `job_events(id, job_id, ts, kind, message, data)`: the per-job timeline shown in the console (not partitioned yet).
- A deployment becomes `completed` when none of its jobs is `queued/sent/accepted/waiting/running`.

Design (original sketch):
```
maintenance_windows(id, org_id, name, days smallint[], start_local time, duration interval,
                    tz_mode[device|fixed], tz)
deployments(id, org_id, name, kind[software|windows_update|reboot|inventory], action,
            spec jsonb, reboot_policy jsonb, window_id, starts_at, deadline_at,
            status[draft|pending_approval|active|paused|completed|cancelled],
            created_by, approved_by, approved_at)
deployment_rings(deployment_id, ordinal, name, group_ids uuid[], device_ids uuid[],
                 start_after interval, success_threshold numeric, status, started_at)
jobs(id, org_id, deployment_id null, ring_ordinal, device_id, user_sid ('' = machine),
     type, payload jsonb, not_before, expires_at, attempt, status, status_reason,
     envelope bytea null, sent_at, acked_at, started_at, finished_at,
     exit_code, result jsonb, reboot_required bool)
job_events(id bigint, job_id, ts, kind, message, data jsonb)    -- partitioned by month
policies(id, org_id, kind[auto_update|baseline|user_scope_app|self_update], spec jsonb,
         target_group_ids uuid[], enabled, created_by, updated_at)
```
Jobs are indexed by `(device_id, status)` for dispatch and `(deployment_id, status)` for progress.

## Windows Update (Phase 4)
Migration `00005_windows_update.sql` (plus `00004`, which adds `jobs.depends_when`). Job types `wu_scan`, `wu_install`, `wu_hide` and `reboot` join the `jobs.type` check.
```
devices += wu_rev, wu_scanned_at, wu_scan_error, wu_reboot_required, wu_policy jsonb (WSUS/WUfB/AU detection),
           wu_service, wu_truncated, wu_settings_rev          -- wu_rev = generation of the last full snapshot applied
org_settings += wu_service[default|windows_update|microsoft_update], wu_include_drivers, wu_rev
wu_updates(org_id, update_id, revision, title, kb[], classification, severity, products[], is_driver, driver_*,
           release_date, support_url, size_bytes, reboot_required, first_seen_at, last_seen_at,
           primary key(org_id, update_id))                      -- every update any device reported (latest revision)
device_updates(device_id, update_id, revision, state[missing|downloaded|hidden|pending_reboot|failed],
               last_error, scanned_at, primary key(device_id, update_id))   -- full replacement per scan
wu_approvals(org_id, update_id, decision[approved|declined|hidden], source[manual|rule], rule_id, note,
             decided_by, decided_at, primary key(org_id, update_id))      -- no row = pending review
wu_rules(id, org_id, name, classifications[], severities[], include_drivers, delay_days, enabled)
wu_rings(id, org_id, name, ordinal 1..20, group_ids[], delay_days, soak_hours, success_threshold 1..100,
         maint_window jsonb, reboot jsonb, enabled)
wu_attempts(org_id, update_id, device_id, ring_id, job_id, state[queued|installed|failed], failures, hresult,
            created_at, finished_at, primary key(update_id, device_id))   -- latest attempt; ring gating reads these
wu_holds(id, org_id, update_id, ring_id, reason, created_at, released_at, released_by)
```
Invariants: approvals are keyed by update identity (not revision), a manual decision is never overwritten by a rule, at most one open hold per (update, ring), and `device_updates` rows exist only for updates the device is *not* fully up to date on (installed updates are not stored).

## Identity, releases and policies (Phase 5)
Migrations `00006_agent_releases`, `00007_identity`, `00008_policies`.
```
agent_releases(id, org_id, version, os, arch, sha256, size, manifest bytea (the exact signed bytes), signature, key_id,
               notes, status[available|withdrawn], uploaded_by, created_at, unique(org_id, version, os, arch))
agent_rollout(org_id pk, release_id, pilot_group_ids[], soak_hours, success_threshold, batch_per_tick, maint_window jsonb,
              paused, paused_reason, started_at, updated_by, updated_at)            -- at most one row per organization
agent_attempts(device_id, release_id, org_id, job_id, pilot, state[queued|updated|failed], failures, last_error,
               created_at, finished_at, pk(device_id, release_id))
users += must_change_password, created_by            -- role_bindings(role, scope_type[org|site], scope_id) already existed
api_tokens(id, org_id, user_id, name, prefix, token_hash (sha256, unique), scopes[], created_at, expires_at,
           last_used_at, last_used_ip, revoked_at)                                   -- the secret is never stored
webauthn_credentials(id, user_id, credential_id unique, record (library JSON), sign_count, name, created_at, last_used_at)
webauthn_ceremonies(id, user_id, kind[register|login], data, expires_at)             -- single use, 5 minutes
software_policies(id, org_id, name, kind[keep_updated|baseline], package_id, group_ids[], delay_days, only_new_devices,
                  unverified_confirmed, maint_window jsonb, enabled, use_rings bool, require_approval bool,
                  created_by, created_at, updated_at, unique(org_id, name))
policy_attempts(policy_id, device_id, version, deployment_id, failures, created_at, pk(policy_id, device_id))
software_approvals(org_id, package_id, version, decision[approved|declined], note, decided_by, decided_at, pk(org_id, package_id, version))
software_holds(id, org_id, policy_id, version, ring_id -> wu_rings, reason, created_at, released_at, released_by,
               unique open hold per (policy_id, version, ring_id))
```
Invariants: at most one open `agent_update` job per device (the planner excludes devices with one); a release that is the rollout target cannot be deleted; the organization always keeps at least one active organization-wide administrator (enforced on disable, delete and role removal); a site cannot be deleted while it has devices or enrollment tokens.

## Audit
```
audit_log(id bigint identity, ts, org_id, actor_type[user|api_token|system|device], actor_id,
          actor_ip, action, target_type, target_ids text[], outcome[success|denied|error],
          details jsonb, prev_hash bytea, hash bytea)
```
- `hash = SHA-256(prev_hash || canonical(row))`. The chain is checked daily, and on demand from the GUI.
- `librepatch_app` cannot run `UPDATE`/`DELETE`/`TRUNCATE` on the table, and a trigger rejects them for every role except the migrator.
- An optional syslog/JSON forwarder streams entries to a SIEM.

## Branding (Phase 7)

Migration `00010_branding` (decision D92). The Down section drops both tables.

```
branding(org_id PK -> organizations, org_name <=120, product_name <=60, accent_color '' | #rrggbb, secondary_color '' | #rrggbb,
         login_headline <=120, login_message <=1000, login_footer <=1000, support_email <=254, support_phone <=40,
         support_url <=300, report_footer <=500, updated_at, updated_by -> users (SET NULL))
branding_assets(org_id, kind IN logo_light|logo_dark|icon|favicon|report_logo, content bytea 1..512 KiB (PNG written by the server),
                content_type = 'image/png', width, height, sha256 (32 bytes), updated_at, updated_by)   -- PK (org_id, kind)
```

An organization without a `branding` row shows the defaults (product "LibrePatch", no organization name). The first-run wizard writes the organization name (and logo) into these tables.

Migration `00011_ui_preferences` (decision D93). The Down section drops `user_preferences` and the two branding columns.

```
branding += default_theme text ('' or ^[a-z][a-z0-9-]{0,31}$), allowed_themes text[] (at most 16; empty = all themes offered)
user_preferences(user_id PK -> users ON DELETE CASCADE, data jsonb (<= 64 KiB: {theme, density, views{tableId:[{id,name,state}]}}), updated_at)
```
