-- Settings and notifications (decision D95).

-- name: GetSettingsSection :one
SELECT * FROM settings_sections WHERE org_id = $1 AND section = $2;

-- name: GetSettingsSectionForUpdate :one
SELECT * FROM settings_sections WHERE org_id = $1 AND section = $2 FOR UPDATE;

-- name: InsertSettingsSection :exec
INSERT INTO settings_sections (org_id, section, revision, schema_version, data, secrets, updated_at, updated_by)
VALUES ($1, $2, 1, $3, $4, $5, $6, $7);

-- name: UpdateSettingsSection :execrows
UPDATE settings_sections SET revision = revision + 1, schema_version = $4, data = $5, secrets = $6, updated_at = $7, updated_by = $8
WHERE org_id = $1 AND section = $2 AND revision = $3;

-- name: FirstOrganization :one
SELECT id FROM organizations ORDER BY created_at, id LIMIT 1;

-- name: EnqueueNotification :exec
INSERT INTO notification_outbox (org_id, channel, event, target, dedupe_key, payload, not_before)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (org_id, channel, target, event, dedupe_key) WHERE dedupe_key <> '' DO NOTHING;

-- name: ClaimDueNotifications :many
SELECT * FROM notification_outbox WHERE status = 'pending' AND not_before <= $1 ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED;

-- name: FinishNotification :exec
UPDATE notification_outbox SET status = $2, attempts = attempts + 1, last_error = $3, not_before = $4, sent_at = $5 WHERE id = $1;

-- name: ListNotificationLog :many
SELECT id, channel, event, target, status, attempts, last_error, created_at, sent_at FROM notification_outbox
WHERE org_id = $1 ORDER BY id DESC LIMIT $2;

-- name: PruneNotificationLog :execrows
DELETE FROM notification_outbox WHERE status <> 'pending' AND created_at < $1;

-- name: OfflineDevicesSince :many
SELECT id, hostname, last_seen_at FROM devices
WHERE org_id = $1 AND status = 'active' AND NOT online AND last_seen_at < $2 ORDER BY last_seen_at LIMIT 500;

-- name: RolloutTargetVersion :one
SELECT r.version, r.created_at FROM agent_rollout o JOIN agent_releases r ON r.id = o.release_id
WHERE o.org_id = $1 AND o.release_id IS NOT NULL;

-- name: ActiveDeviceAgents :many
SELECT id, hostname, agent_version FROM devices WHERE org_id = $1 AND status = 'active' AND agent_version <> '' ORDER BY id LIMIT 20000;

-- name: PruneFinishedJobs :execrows
DELETE FROM jobs WHERE org_id = $1 AND status IN ('succeeded', 'succeeded_reboot', 'failed', 'expired', 'cancelled', 'rejected') AND COALESCE(finished_at, created_at) < $2;

-- name: PruneSoftwareHistory :execrows
-- One batch of an organization's software change history older than $2 (the caller repeats until a batch comes back
-- short, so the first run on a big table is many small statements, not one that hits the statement timeout).
DELETE FROM software_history WHERE id IN (
  SELECT h.id FROM software_history h JOIN devices d ON d.id = h.device_id
  WHERE d.org_id = @org_id::uuid AND h.observed_at < @before::timestamptz
  ORDER BY h.id LIMIT 20000);

-- name: ListDeviceCustomValues :many
SELECT field_key, value FROM device_custom_values WHERE device_id = $1 ORDER BY field_key;

-- name: ListCustomValuesForDevices :many
SELECT device_id, field_key, value FROM device_custom_values WHERE device_id = ANY(@device_ids::uuid[]);

-- name: UpsertDeviceCustomValue :exec
INSERT INTO device_custom_values (device_id, field_key, value, updated_at, updated_by) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (device_id, field_key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by;

-- name: DeleteDeviceCustomValue :exec
DELETE FROM device_custom_values WHERE device_id = $1 AND field_key = $2;

-- name: ListStaleDevices :many
SELECT id, hostname FROM devices WHERE org_id = $1 AND status IN ('revoked', 'retired') AND COALESCE(last_seen_at, revoked_at, enrolled_at) < $2 ORDER BY id LIMIT 200;

-- name: LastAuditByAction :one
SELECT ts, details FROM audit_log WHERE org_id = $1 AND action = $2 ORDER BY id DESC LIMIT 1;

-- name: LastBackupAudit :one
SELECT ts, details FROM audit_log WHERE action = 'admin.backup' ORDER BY id DESC LIMIT 1;

-- name: DataFootprint :one
SELECT (SELECT count(*) FROM jobs j WHERE j.org_id = $1)::bigint AS jobs,
       (SELECT count(*) FROM compliance_snapshots c WHERE c.org_id = $1)::bigint AS snapshots,
       (SELECT count(*) FROM notification_outbox n WHERE n.org_id = $1)::bigint AS notifications,
       (SELECT count(*) FROM audit_log a WHERE a.org_id = $1)::bigint AS audit_entries,
       (SELECT min(a2.ts) FROM audit_log a2 WHERE a2.org_id = $1) AS audit_since;

-- name: InsertReportRun :execrows
INSERT INTO report_runs (org_id, schedule_id, due_at, started_at, name, report, format, status)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING;

-- name: FinishReportRun :exec
UPDATE report_runs SET status = $4, error = $5, bytes = $6, recipients = $7 WHERE org_id = $1 AND schedule_id = $2 AND due_at = $3;

-- name: CountReportRuns :one
SELECT count(*)::bigint FROM report_runs WHERE org_id = $1 AND schedule_id = $2;

-- name: ListReportRuns :many
SELECT * FROM report_runs WHERE org_id = $1 ORDER BY started_at DESC LIMIT $2;

-- name: PruneReportRuns :execrows
DELETE FROM report_runs WHERE started_at < $1;

-- name: ListActiveDevicesForReport :many
SELECT hostname, os_caption, os_build, manufacturer, model, serial, logged_on_user, online, last_seen_at, agent_version, site_id
FROM devices WHERE org_id = $1 AND status = 'active' ORDER BY lower(hostname), id LIMIT 20000;
