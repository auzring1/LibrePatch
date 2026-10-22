-- name: InsertSoftwarePolicy :exec
INSERT INTO software_policies (id, org_id, name, kind, package_id, group_ids, delay_days, only_new_devices, unverified_confirmed, maint_window, enabled, created_by, use_rings, require_approval, prompts)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15);

-- name: UpdateSoftwarePolicy :execrows
UPDATE software_policies SET name = $3, kind = $4, package_id = $5, group_ids = $6, delay_days = $7, only_new_devices = $8,
    unverified_confirmed = $9, maint_window = $10, enabled = $11, use_rings = $12, require_approval = $13, prompts = $14, updated_at = now()
WHERE id = $1 AND org_id = $2 AND auto_policy_id IS NULL;

-- name: DeleteSoftwarePolicy :execrows
DELETE FROM software_policies WHERE id = $1 AND org_id = $2 AND auto_policy_id IS NULL;

-- name: GetSoftwarePolicy :one
SELECT * FROM software_policies WHERE id = $1 AND org_id = $2;

-- name: ListSoftwarePolicies :many
SELECT p.*, k.name AS package_name, k.identifier AS package_identifier
FROM software_policies p JOIN catalog_packages k ON k.id = p.package_id
WHERE p.org_id = $1 AND p.auto_policy_id IS NULL ORDER BY lower(p.name);

-- name: ListEnabledSoftwarePolicies :many
SELECT * FROM software_policies WHERE enabled ORDER BY created_at, id;

-- name: ListOutdatedForPackage :many
-- Machine-wide copies of a package (matched by normalized name) older than the target version.
SELECT DISTINCT ON (si.device_id) si.device_id, si.version
FROM software_installs si JOIN software_titles st ON st.id = si.title_id
WHERE si.device_id = ANY(@device_ids::uuid[]) AND NOT si.system_component AND si.scope = 'machine'
  AND st.normalized_name = @normalized_name::text AND si.version_key IS NOT NULL AND si.version_key < @version_key::bytea
ORDER BY si.device_id, si.version_key DESC;

-- name: ListDevicesWithPackage :many
SELECT DISTINCT si.device_id
FROM software_installs si JOIN software_titles st ON st.id = si.title_id
WHERE si.device_id = ANY(@device_ids::uuid[]) AND NOT si.system_component AND st.normalized_name = @normalized_name::text;

-- name: ListDevicesWithCurrentPackage :many
SELECT DISTINCT si.device_id
FROM software_installs si JOIN software_titles st ON st.id = si.title_id
WHERE si.device_id = ANY(@device_ids::uuid[]) AND NOT si.system_component AND st.normalized_name = @normalized_name::text
  AND si.version_key IS NOT NULL AND si.version_key >= @version_key::bytea;

-- name: ListDeviceEnrollTimes :many
SELECT id, enrolled_at FROM devices WHERE id = ANY($1::uuid[]);

-- name: ListPolicyAttempts :many
SELECT * FROM policy_attempts WHERE policy_id = $1 AND device_id = ANY($2::uuid[]);

-- name: UpsertPolicyAttempt :exec
INSERT INTO policy_attempts (policy_id, device_id, version, deployment_id, failures, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (policy_id, device_id) DO UPDATE SET version = EXCLUDED.version, deployment_id = EXCLUDED.deployment_id,
    failures = EXCLUDED.failures, created_at = EXCLUDED.created_at;

-- name: PolicyJobStates :many
-- Whether a device's install/update job of a deployment is still open, failed or succeeded.
SELECT deployment_id, device_id,
       bool_or(status IN ('queued', 'sent', 'accepted', 'waiting', 'running')) AS is_open,
       bool_or(status IN ('failed', 'expired', 'cancelled', 'rejected')) AS failed,
       bool_or(status IN ('succeeded', 'succeeded_reboot')) AS ok
FROM jobs
WHERE deployment_id = ANY($1::uuid[]) AND type IN ('software_install', 'software_update')
GROUP BY deployment_id, device_id;

-- name: PolicyAttemptStats :one
SELECT count(*)::bigint AS devices, COALESCE(sum(failures), 0)::bigint AS failures FROM policy_attempts WHERE policy_id = $1;

-- ---- reports ----

-- name: ComplianceReport :many
SELECT d.id, d.hostname, d.site_id, d.os_caption, d.os_build, d.online, d.last_seen_at, d.wu_scanned_at, d.agent_version,
       (d.pending_reboot OR
        CASE WHEN d.wu_reboot_required AND d.wu_scanned_at IS NOT NULL AND d.last_seen_at IS NOT NULL AND d.uptime_s > 0
             -- The "restart required" of a Windows Update scan only counts if the scan was taken after the last boot
             -- (last boot = the last heartbeat minus the uptime it reported). Otherwise it is a leftover that stays
             -- until the next scan, long after the person restarted.
             THEN d.wu_scanned_at >= d.last_seen_at - make_interval(secs => d.uptime_s::float8)
             ELSE d.wu_reboot_required END) AS reboot_pending,
       (count(du.update_id) FILTER (WHERE a.decision = 'approved'))::int AS approved_missing,
       (count(du.update_id) FILTER (WHERE u.severity = 'Critical' AND COALESCE(a.decision, '') <> 'declined'))::int AS critical_missing,
       (count(du.update_id) FILTER (WHERE du.state = 'failed'))::int AS failed_updates
FROM devices d
LEFT JOIN device_updates du ON du.device_id = d.id AND du.state IN ('missing', 'downloaded', 'failed')
LEFT JOIN wu_updates u ON u.org_id = d.org_id AND u.update_id = du.update_id
LEFT JOIN wu_approvals a ON a.org_id = d.org_id AND a.update_id = du.update_id
WHERE d.org_id = $1 AND d.status = 'active'
GROUP BY d.id
ORDER BY lower(d.hostname), d.id;

-- name: ReportJobCounts :many
SELECT type, status, count(*)::bigint AS n FROM jobs WHERE org_id = $1 AND created_at > $2 GROUP BY type, status;

-- name: ReportDeviceCounts :one
SELECT count(*) FILTER (WHERE status = 'active')::bigint AS active,
       count(*) FILTER (WHERE status = 'pending')::bigint AS pending,
       count(*) FILTER (WHERE status = 'revoked')::bigint AS revoked,
       count(*) FILTER (WHERE status = 'active' AND online)::bigint AS online,
       count(*) FILTER (WHERE status = 'active' AND last_seen_at < @stale_before::timestamptz)::bigint AS stale
FROM devices WHERE org_id = @org_id;


-- ---- approvals and rings (D121) ----

-- name: GetSoftwareApproval :one
SELECT * FROM software_approvals WHERE org_id = $1 AND package_id = $2 AND version = $3;

-- name: UpsertSoftwareApproval :exec
INSERT INTO software_approvals (org_id, package_id, version, decision, note, decided_by, decided_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (org_id, package_id, version) DO UPDATE SET decision = EXCLUDED.decision, note = EXCLUDED.note,
    decided_by = EXCLUDED.decided_by, decided_at = EXCLUDED.decided_at;

-- name: DeleteSoftwareApproval :execrows
DELETE FROM software_approvals WHERE org_id = $1 AND package_id = $2 AND version = $3;

-- name: ListRecentSoftwareApprovals :many
SELECT a.package_id, k.name AS package_name, a.version, a.decision, a.note, a.decided_at, COALESCE(u.display_name, '') AS decided_by_name
FROM software_approvals a JOIN catalog_packages k ON k.id = a.package_id LEFT JOIN users u ON u.id = a.decided_by
WHERE a.org_id = $1 AND a.decided_at >= $2 ORDER BY a.decided_at DESC LIMIT 50;

-- name: ListPolicyAttemptsForVersion :many
SELECT device_id, deployment_id, failures, created_at FROM policy_attempts WHERE policy_id = $1 AND version = $2;

-- name: InsertSoftwareHold :execrows
INSERT INTO software_holds (id, org_id, policy_id, version, ring_id, reason)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (policy_id, version, ring_id) WHERE released_at IS NULL DO NOTHING;

-- name: ListSoftwareHoldsForVersion :many
SELECT id, ring_id, released_at FROM software_holds WHERE policy_id = $1 AND version = $2;

-- name: GetSoftwareHold :one
SELECT h.*, p.name AS policy_name FROM software_holds h JOIN software_policies p ON p.id = h.policy_id WHERE h.id = $1 AND h.org_id = $2;

-- name: ReleaseSoftwareHold :execrows
UPDATE software_holds SET released_at = now(), released_by = $3 WHERE id = $1 AND org_id = $2 AND released_at IS NULL;

-- name: ListOpenSoftwareHolds :many
SELECT h.id, h.policy_id, p.name AS policy_name, k.name AS package_name, h.version, r.name AS ring_name, h.reason, h.created_at
FROM software_holds h
JOIN software_policies p ON p.id = h.policy_id
JOIN catalog_packages k ON k.id = p.package_id
JOIN wu_rings r ON r.id = h.ring_id
WHERE h.org_id = $1 AND h.released_at IS NULL ORDER BY h.created_at DESC;


-- ---- what the last check found (D132) ----

-- name: SetPolicyStatus :exec
-- What the last check found. A deployment created by the check also sets the time and id of the last run.
UPDATE software_policies SET last_check_at = @checked_at,
    last_state = @state, last_detail = @detail,
    last_run_at = COALESCE(@run_at, last_run_at), last_deployment_id = COALESCE(@deployment_id, last_deployment_id)
WHERE id = @id;

-- ---- all-apps policies (D132) ----

-- name: InsertAutoPolicy :exec
INSERT INTO software_auto_policies (id, org_id, name, group_ids, delay_days, maint_window, enabled, use_rings, require_approval, prompts, filter, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: UpdateAutoPolicy :execrows
UPDATE software_auto_policies SET name = $3, group_ids = $4, delay_days = $5, maint_window = $6, enabled = $7, use_rings = $8,
    require_approval = $9, prompts = $10, filter = $11, updated_at = now()
WHERE id = $1 AND org_id = $2;

-- name: DeleteAutoPolicy :execrows
DELETE FROM software_auto_policies WHERE id = $1 AND org_id = $2;

-- name: GetAutoPolicy :one
SELECT * FROM software_auto_policies WHERE id = $1 AND org_id = $2;

-- name: ListAutoPolicies :many
SELECT * FROM software_auto_policies WHERE org_id = $1 ORDER BY lower(name);

-- name: ListEnabledAutoPolicies :many
SELECT * FROM software_auto_policies WHERE enabled ORDER BY created_at, id;

-- name: SetAutoPolicyStatus :exec
UPDATE software_auto_policies SET last_check_at = @checked_at, last_state = @state, last_detail = @detail WHERE id = @id;

-- name: ListAutoChildren :many
SELECT p.*, k.name AS package_name, k.identifier AS package_identifier, k.verified AS package_verified, k.source AS package_source
FROM software_policies p JOIN catalog_packages k ON k.id = p.package_id
WHERE p.auto_policy_id = $1 ORDER BY lower(k.name);

-- name: InsertAutoChild :exec
INSERT INTO software_policies (id, org_id, name, kind, package_id, group_ids, delay_days, only_new_devices, unverified_confirmed, maint_window, enabled,
    created_by, use_rings, require_approval, prompts, auto_policy_id)
VALUES ($1, $2, $3, 'keep_updated', $4, $5, $6, false, $7, $8, $9, $10, $11, $12, $13, $14);

-- name: DeleteAutoChild :exec
DELETE FROM software_policies WHERE id = $1 AND auto_policy_id IS NOT NULL;

-- name: PropagateAutoPolicy :exec
-- The all-apps policy's settings are the settings of each of its children (the prompts differ per app, so one at a time).
UPDATE software_policies SET group_ids = $2, delay_days = $3, maint_window = $4, enabled = $5, use_rings = $6, require_approval = $7,
    prompts = $8, unverified_confirmed = $9, updated_at = now()
WHERE id = $1 AND auto_policy_id IS NOT NULL;

-- name: PackageHasManualPolicy :one
-- A policy somebody made by hand for the package. When one appears, the all-apps policy gives the package up.
SELECT EXISTS (
    SELECT 1 FROM software_policies
    WHERE org_id = @org_id AND package_id = @package_id AND enabled AND kind = 'keep_updated' AND auto_policy_id IS NULL
) AS owned;

-- name: PackageHasOtherPolicy :one
-- A package that another enabled policy already handles (a policy made by hand for that package, or a child of another
-- all-apps policy) is left to that policy, so one device is not deployed to twice.
SELECT EXISTS (
    SELECT 1 FROM software_policies
    WHERE org_id = @org_id AND package_id = @package_id AND enabled AND kind = 'keep_updated'
      AND (auto_policy_id IS NULL OR auto_policy_id IS DISTINCT FROM @auto_policy_id)
) AS owned;

-- name: AutoPolicyAttemptStats :one
SELECT COALESCE(sum(c.devices), 0)::bigint AS devices FROM (
    SELECT count(*) AS devices FROM policy_attempts a JOIN software_policies p ON p.id = a.policy_id WHERE p.auto_policy_id = $1 GROUP BY a.policy_id
) c;

-- name: ListAutomatedPackages :many
-- The packages an enabled policy keeps up to date (a policy made by hand, or an app of an all-apps policy).
SELECT DISTINCT package_id FROM software_policies WHERE org_id = $1 AND enabled AND kind = 'keep_updated';

-- name: HasEnabledAllAppsPolicy :one
SELECT EXISTS (SELECT 1 FROM software_auto_policies WHERE org_id = $1 AND enabled) AS present;
