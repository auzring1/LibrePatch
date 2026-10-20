-- name: InsertDeployment :exec
INSERT INTO deployments (id, org_id, name, action, package_id, version_id, scope, target_group_ids, target_device_ids,
    starts_at, expires_at, maint_window, unverified_confirmed, status, created_by, prompts)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'active', $14, $15);

-- name: GetDeployment :one
SELECT d.*, p.name AS package_name, p.identifier AS package_identifier, v.version AS version
FROM deployments d
JOIN catalog_packages p ON p.id = d.package_id
LEFT JOIN catalog_versions v ON v.id = d.version_id
WHERE d.id = $1 AND d.org_id = $2;

-- name: ListDeployments :many
SELECT d.id, d.name, d.action, d.scope, d.status, d.created_at, d.starts_at, d.expires_at,
       p.name AS package_name, p.identifier AS package_identifier, v.version AS version,
       (SELECT count(*) FROM jobs j WHERE j.deployment_id = d.id)::int AS jobs_total,
       (SELECT count(*) FROM jobs j WHERE j.deployment_id = d.id AND j.status IN ('succeeded','succeeded_reboot'))::int AS jobs_succeeded,
       (SELECT count(*) FROM jobs j WHERE j.deployment_id = d.id AND j.status IN ('failed','rejected','expired','cancelled'))::int AS jobs_failed
FROM deployments d
JOIN catalog_packages p ON p.id = d.package_id
LEFT JOIN catalog_versions v ON v.id = d.version_id
WHERE d.org_id = $1
ORDER BY d.created_at DESC, d.id
LIMIT $2 OFFSET $3;

-- name: SetDeploymentStatus :exec
UPDATE deployments SET status = $3 WHERE id = $1 AND org_id = $2;

-- name: DeploymentJobCounts :many
SELECT status, count(*)::int AS n FROM jobs WHERE deployment_id = $1 GROUP BY status;

-- name: CompleteDeploymentIfDone :exec
UPDATE deployments d SET status = 'completed'
WHERE d.id = $1 AND d.status = 'active'
  AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.deployment_id = $1 AND j.status IN ('queued','sent','accepted','waiting','running'));

-- name: ListActiveDevicesByIDs :many
SELECT id, hostname, arch FROM devices WHERE org_id = $1 AND status = 'active' AND id = ANY($2::uuid[]) ORDER BY lower(hostname), id;

-- name: ListStaticGroupDeviceIDs :many
SELECT m.device_id FROM group_members m JOIN groups g ON g.id = m.group_id
WHERE g.org_id = $1 AND g.id = ANY($2::uuid[]) AND g.kind = 'static';

-- name: ListPackageInstalls :many
SELECT si.device_id, si.source, si.scope, si.user_sid, si.item_key, si.version, si.version_key, si.name
FROM software_installs si JOIN software_titles st ON st.id = si.title_id
WHERE st.org_id = @org_id::uuid AND si.device_id = ANY(@device_ids::uuid[]) AND st.normalized_name = @normalized_name::text
  AND NOT si.system_component;

-- name: ListInstallRowsForDevices :many
-- Everything these devices report that an installer could update (store apps and portable programs are left out),
-- with what the winget index needs to recognise it. Used to find installed copies whose display name differs from
-- the package's.
SELECT si.device_id, si.source, si.scope, si.user_sid, si.item_key, si.name, si.version, si.version_key, si.publisher, si.product_code
FROM software_installs si
WHERE si.device_id = ANY(@device_ids::uuid[]) AND NOT si.system_component AND si.source NOT IN ('appx', 'portable')
ORDER BY si.device_id, lower(si.name), si.scope, si.user_sid, si.item_key;

-- name: ListDeviceUsersForDevices :many
SELECT device_id, sid, username FROM device_users WHERE device_id = ANY($1::uuid[]) AND profile_path <> '' ORDER BY device_id, sid;

-- name: InsertJob :exec
INSERT INTO jobs (id, org_id, deployment_id, device_id, user_sid, type, title, body, depends_on, depends_when, not_before, expires_at, attempt)
VALUES (@id, @org_id, @deployment_id, @device_id, @user_sid, @type, @title, @body, @depends_on,
        COALESCE(NULLIF(@depends_when::text, ''), 'success'), @not_before, @expires_at, @attempt);

-- name: GetJob :one
SELECT * FROM jobs WHERE id = $1 AND org_id = $2;

-- name: GetJobForDevice :one
SELECT * FROM jobs WHERE id = $1 AND device_id = $2;

-- name: ListJobsByDeployment :many
SELECT j.id, j.device_id, d.hostname, j.user_sid, j.type, j.title, j.status, j.status_reason, j.attempt, j.created_at,
       j.sent_at, j.acked_at, j.started_at, j.finished_at, j.exit_code, j.detection_passed, j.reboot_required,
       j.depends_on, j.expires_at, j.not_before
FROM jobs j JOIN devices d ON d.id = j.device_id
WHERE j.deployment_id = $1 AND j.org_id = $2
ORDER BY lower(d.hostname), j.user_sid, j.created_at, j.id
LIMIT $3 OFFSET $4;

-- name: ListDeviceJobs :many
SELECT j.id, j.deployment_id, j.user_sid, j.type, j.title, j.status, j.status_reason, j.attempt, j.created_at,
       j.finished_at, j.exit_code, j.reboot_required
FROM jobs j WHERE j.device_id = $1 AND j.org_id = $2
ORDER BY j.created_at DESC, j.id DESC LIMIT $3;

-- name: ListDispatchableJobs :many
-- Jobs the device should hold: not yet acknowledged, still valid, dependencies satisfied.
SELECT j.* FROM jobs j
WHERE j.device_id = $1 AND j.status IN ('queued', 'sent') AND j.expires_at > now()
  AND (j.depends_on IS NULL OR EXISTS (SELECT 1 FROM jobs p WHERE p.id = j.depends_on AND (
        p.status IN ('succeeded', 'succeeded_reboot')
        OR (j.depends_when = 'finished' AND p.status IN ('failed', 'expired', 'rejected')))))
ORDER BY j.not_before, j.created_at, j.id;

-- name: MarkJobSent :exec
UPDATE jobs SET status = CASE WHEN status = 'queued' THEN 'sent' ELSE status END, envelope = $2, sent_at = $3 WHERE id = $1;

-- name: ApplyJobUpdate :execrows
UPDATE jobs SET status = @status::text, status_reason = @reason::text,
    acked_at = COALESCE(acked_at, @now::timestamptz),
    started_at = COALESCE(started_at, @started_at),
    finished_at = COALESCE(@finished_at, finished_at),
    exit_code = COALESCE(@exit_code, exit_code),
    detection_passed = COALESCE(@detection_passed, detection_passed),
    reboot_required = reboot_required OR @reboot_required::boolean,
    result = COALESCE(@result, result)
WHERE id = @id::uuid AND device_id = @device_id::uuid
  AND status NOT IN ('succeeded', 'succeeded_reboot', 'failed', 'expired', 'cancelled', 'rejected');

-- name: InsertJobEvent :exec
INSERT INTO job_events (job_id, kind, message, data) VALUES ($1, $2, $3, $4);

-- name: ListJobEvents :many
SELECT id, ts, kind, message, data FROM job_events WHERE job_id = $1 ORDER BY id LIMIT 500;

-- name: ExpireJobs :many
UPDATE jobs SET status = 'expired', status_reason = 'expired', finished_at = $1
WHERE status IN ('queued', 'sent', 'accepted', 'waiting') AND expires_at < $1
RETURNING id, device_id, deployment_id, org_id;

-- name: ListDependentJobs :many
SELECT * FROM jobs WHERE depends_on = $1 AND status = 'queued';

-- name: CancelJobsOfDeployment :many
UPDATE jobs SET status = 'cancelled', status_reason = 'deployment_cancelled', finished_at = $2
WHERE deployment_id = $1 AND status IN ('queued', 'sent', 'accepted', 'waiting')
RETURNING id, device_id, status;

-- name: CancelJob :execrows
UPDATE jobs SET status = 'cancelled', status_reason = $3, finished_at = $4
WHERE id = $1 AND org_id = $2 AND status IN ('queued', 'sent', 'accepted', 'waiting', 'running');

-- name: DeviceOnlineStatus :one
SELECT online FROM devices WHERE id = $1;

-- name: MarkCancelPending :exec
UPDATE jobs SET cancel_pending = true WHERE id = $1 AND acked_at IS NOT NULL;

-- name: ListCancelPending :many
SELECT id FROM jobs WHERE device_id = $1 AND cancel_pending AND finished_at > now() - interval '30 days';

-- name: ClearCancelPending :exec
UPDATE jobs SET cancel_pending = false WHERE id = $1 AND device_id = $2;

-- name: FindRecentRefresh :one
SELECT id FROM jobs
WHERE device_id = $1 AND type = 'inventory_full' AND status IN ('queued', 'sent', 'accepted', 'waiting', 'running')
  AND created_at > now() - interval '2 minutes'
ORDER BY created_at DESC LIMIT 1;
