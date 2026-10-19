-- name: CreateEnrollmentToken :exec
INSERT INTO enrollment_tokens (id, org_id, site_id, name, token_hash, max_uses, expires_at,
                               require_approval, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: ListEnrollmentTokens :many
SELECT * FROM enrollment_tokens WHERE org_id = $1 ORDER BY created_at DESC LIMIT 500;

-- name: GetEnrollmentTokenByHashForUpdate :one
SELECT * FROM enrollment_tokens WHERE token_hash = $1 FOR UPDATE;

-- name: IncrementEnrollmentTokenUse :exec
UPDATE enrollment_tokens SET used_count = used_count + 1 WHERE id = $1;

-- name: RevokeEnrollmentToken :execrows
UPDATE enrollment_tokens SET revoked_at = $3 WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL;

-- name: GetEnrollmentTokenInOrg :one
SELECT * FROM enrollment_tokens WHERE id = $1 AND org_id = $2 FOR UPDATE;

-- name: DeleteEnrollmentToken :execrows
DELETE FROM enrollment_tokens WHERE id = $1 AND org_id = $2;

-- name: CreateDevice :exec
INSERT INTO devices (id, org_id, site_id, status, hostname, smbios_uuid, serial, os_build, arch,
                     agent_version, enrolled_via, replaces_device_id, enroll_ticket_hash, pending_csr,
                     approved_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15);

-- name: GetDevice :one
SELECT * FROM devices WHERE id = $1;

-- name: GetDeviceInOrg :one
SELECT * FROM devices WHERE id = $1 AND org_id = $2;

-- name: GetDeviceByTicketHash :one
SELECT * FROM devices WHERE enroll_ticket_hash = $1;

-- name: FindActiveDeviceByHardware :one
SELECT * FROM devices
WHERE org_id = $1 AND status = 'active' AND smbios_uuid = $2 AND serial = $3
  AND smbios_uuid <> '' AND serial <> ''
ORDER BY enrolled_at DESC LIMIT 1;

-- name: ListDevices :many
SELECT id, org_id, site_id, status, status_reason, hostname, os_caption, os_build, arch, agent_version,
       enrolled_at, approved_at, revoked_at, last_seen_at, online, last_ip, uptime_s, pending_reboot,
       logged_on_user, serial, replaces_device_id, manufacturer, model, chassis, software_count, software_updated_at
FROM devices
WHERE org_id = $1
  AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('site_ids')::uuid[] IS NULL OR site_id = ANY(sqlc.narg('site_ids')::uuid[]))
ORDER BY (status = 'pending') DESC, hostname, id
LIMIT $2 OFFSET $3;

-- name: CountDevices :one
SELECT count(*) FROM devices
WHERE org_id = $1 AND (sqlc.narg('status')::text IS NULL OR status = sqlc.narg('status')::text)
  AND (sqlc.narg('site_ids')::uuid[] IS NULL OR site_id = ANY(sqlc.narg('site_ids')::uuid[]));

-- name: ApproveDevice :execrows
UPDATE devices SET status = 'active', approved_by = $3, approved_at = $4
WHERE id = $1 AND org_id = $2 AND status = 'pending';

-- name: RevokeDevice :execrows
UPDATE devices SET status = 'revoked', status_reason = $3, revoked_by = $4, revoked_at = $5,
                   online = false, enroll_ticket_hash = NULL, pending_csr = NULL
WHERE id = $1 AND org_id = $2 AND status IN ('pending', 'active');

-- name: DeleteDeviceCerts :exec
DELETE FROM device_certs WHERE device_id = $1;

-- name: ClearReplacesDevice :exec
UPDATE devices SET replaces_device_id = NULL WHERE replaces_device_id = $1;

-- name: DeleteDevice :execrows
-- Only a revoked or retired device may be removed; inventory, jobs and group membership cascade.
DELETE FROM devices WHERE id = $1 AND org_id = $2 AND status IN ('revoked', 'retired');

-- name: CompleteDeviceEnrollment :exec
UPDATE devices SET enroll_ticket_hash = NULL, pending_csr = NULL WHERE id = $1;

-- name: SetDeviceOnline :exec
UPDATE devices SET online = $2, last_ip = $3, last_seen_at = $4, agent_version = $5 WHERE id = $1;

-- name: SetDeviceOffline :exec
UPDATE devices SET online = false, last_seen_at = $2 WHERE id = $1;

-- name: MarkAllDevicesOffline :exec
UPDATE devices SET online = false WHERE online;

-- name: UpdateDeviceHeartbeat :exec
UPDATE devices SET last_seen_at = $2, uptime_s = $3, pending_reboot = $4, logged_on_user = $5, system_drive_free_bytes = $6 WHERE id = $1;

-- name: UpdateDeviceHardware :execrows
UPDATE devices
SET hardware = $2, hardware_rev = $3, hardware_updated_at = $4, hostname = $5, os_caption = $6,
    os_build = $7, arch = $8, serial = $9, pending_reboot = $10
-- Hardware is a full snapshot sent in order on one stream: latest wins.
WHERE id = $1;
