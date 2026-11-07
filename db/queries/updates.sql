-- ---- ingest ----

-- name: UpsertWuUpdates :exec
INSERT INTO wu_updates (org_id, update_id, revision, title, kb, classification, severity, products, is_driver,
                        driver_class, driver_hwid, driver_version, release_date, support_url, size_bytes, reboot_required)
SELECT @org_id::uuid, t.update_id, t.revision, t.title, COALESCE(string_to_array(NULLIF(t.kb, ''), ','), '{}'::text[]),
       t.classification, t.severity, COALESCE(string_to_array(NULLIF(t.products, ''), '|'), '{}'::text[]), t.is_driver,
       t.driver_class, t.driver_hwid, t.driver_version, to_timestamp(NULLIF(t.release_unix, 0)), t.support_url, t.size_bytes, t.reboot_required
FROM unnest(@update_ids::uuid[], @revisions::int[], @titles::text[], @kbs::text[], @classifications::text[], @severities::text[],
            @products::text[], @is_drivers::bool[], @driver_classes::text[], @driver_hwids::text[], @driver_versions::text[],
            @release_unix::bigint[], @support_urls::text[], @sizes::bigint[], @reboots::bool[])
     AS t(update_id, revision, title, kb, classification, severity, products, is_driver, driver_class, driver_hwid,
          driver_version, release_unix, support_url, size_bytes, reboot_required)
ON CONFLICT (org_id, update_id) DO UPDATE SET
    revision = GREATEST(wu_updates.revision, EXCLUDED.revision),
    title = CASE WHEN EXCLUDED.revision >= wu_updates.revision THEN EXCLUDED.title ELSE wu_updates.title END,
    kb = CASE WHEN EXCLUDED.revision >= wu_updates.revision THEN EXCLUDED.kb ELSE wu_updates.kb END,
    classification = CASE WHEN EXCLUDED.revision >= wu_updates.revision THEN EXCLUDED.classification ELSE wu_updates.classification END,
    severity = CASE WHEN EXCLUDED.revision >= wu_updates.revision THEN EXCLUDED.severity ELSE wu_updates.severity END,
    products = CASE WHEN EXCLUDED.revision >= wu_updates.revision THEN EXCLUDED.products ELSE wu_updates.products END,
    support_url = CASE WHEN EXCLUDED.revision >= wu_updates.revision THEN EXCLUDED.support_url ELSE wu_updates.support_url END,
    size_bytes = GREATEST(wu_updates.size_bytes, EXCLUDED.size_bytes),
    reboot_required = wu_updates.reboot_required OR EXCLUDED.reboot_required,
    last_seen_at = now();

-- name: DeleteDeviceUpdates :exec
DELETE FROM device_updates WHERE device_id = $1;

-- name: InsertDeviceUpdates :exec
INSERT INTO device_updates (device_id, update_id, revision, state, last_error, scanned_at)
SELECT @device_id::uuid, t.update_id, t.revision, t.state, t.last_error, @scanned_at::timestamptz
FROM unnest(@update_ids::uuid[], @revisions::int[], @states::text[], @errors::text[]) AS t(update_id, revision, state, last_error);

-- name: SetDeviceWU :exec
UPDATE devices SET wu_rev = $2, wu_scanned_at = $3, wu_scan_error = $4, wu_reboot_required = $5, wu_policy = $6,
                   wu_service = $7, wu_truncated = $8
WHERE id = $1;

-- name: LockDeviceForWU :one
SELECT org_id FROM devices WHERE id = $1 FOR UPDATE;

-- name: PruneWuUpdates :execrows
DELETE FROM wu_updates u
WHERE u.last_seen_at < now() - interval '90 days'
  AND NOT EXISTS (SELECT 1 FROM device_updates d WHERE d.update_id = u.update_id)
  AND NOT EXISTS (SELECT 1 FROM wu_approvals a WHERE a.org_id = u.org_id AND a.update_id = u.update_id);

-- ---- catalog and device views ----

-- name: ListUpdateCatalog :many
SELECT u.update_id, u.revision, u.title, u.kb, u.classification, u.severity, u.products, u.is_driver, u.release_date,
       u.reboot_required, u.support_url, u.first_seen_at,
       COALESCE(a.decision, '')::text AS decision, COALESCE(a.source, '')::text AS decision_source, a.decided_at, a.decided_by,
       COALESCE(a.note, '')::text AS note,
       (SELECT count(*) FROM device_updates d JOIN devices dv ON dv.id = d.device_id
         WHERE d.update_id = u.update_id AND dv.org_id = u.org_id AND dv.status = 'active' AND d.state IN ('missing', 'downloaded'))::int AS devices_missing,
       (SELECT count(*) FROM device_updates d JOIN devices dv ON dv.id = d.device_id
         WHERE d.update_id = u.update_id AND dv.org_id = u.org_id AND dv.status = 'active' AND d.state = 'pending_reboot')::int AS devices_pending_reboot,
       (SELECT count(*) FROM wu_attempts t WHERE t.update_id = u.update_id AND t.org_id = u.org_id AND t.state = 'installed')::int AS devices_installed,
       (SELECT count(*) FROM wu_attempts t WHERE t.update_id = u.update_id AND t.org_id = u.org_id AND t.state = 'failed')::int AS devices_failed,
       (SELECT count(*) FROM wu_holds h WHERE h.update_id = u.update_id AND h.org_id = u.org_id AND h.released_at IS NULL)::int AS holds,
       count(*) OVER ()::int AS total_count
FROM wu_updates u
LEFT JOIN wu_approvals a ON a.org_id = u.org_id AND a.update_id = u.update_id
WHERE u.org_id = @org_id::uuid
  AND (@q::text = '' OR strpos(lower(u.title), @q::text) > 0 OR EXISTS (SELECT 1 FROM unnest(u.kb) k WHERE strpos(lower(k), @q::text) > 0))
  AND (@classification::text = '' OR u.classification = @classification::text)
  AND (@severity::text = '' OR u.severity = @severity::text)
  AND (@decision::text = '' OR COALESCE(a.decision, 'pending') = @decision::text)
  AND (NOT @only_missing::boolean OR EXISTS (SELECT 1 FROM device_updates d JOIN devices dv ON dv.id = d.device_id
        WHERE d.update_id = u.update_id AND dv.org_id = u.org_id AND dv.status = 'active' AND d.state IN ('missing', 'downloaded')))
ORDER BY u.release_date DESC NULLS LAST, u.update_id
LIMIT @row_limit::int OFFSET @row_offset::int;

-- name: GetUpdate :one
SELECT * FROM wu_updates WHERE org_id = $1 AND update_id = $2;

-- name: ListUpdateDevices :many
SELECT d.id AS device_id, d.hostname, d.online, du.state, du.last_error, du.scanned_at, du.revision,
       COALESCE(t.state, '')::text AS attempt_state, COALESCE(t.failures, 0)::int AS attempt_failures, t.finished_at AS attempt_finished_at,
       COALESCE(r.name, '')::text AS ring_name
FROM device_updates du
JOIN devices d ON d.id = du.device_id
LEFT JOIN wu_attempts t ON t.update_id = du.update_id AND t.device_id = du.device_id
LEFT JOIN wu_rings r ON r.id = t.ring_id
WHERE d.org_id = $1 AND du.update_id = $2
ORDER BY lower(d.hostname), d.id
LIMIT $3 OFFSET $4;

-- name: ListDeviceWUpdates :many
SELECT du.update_id, du.revision, du.state, du.last_error, du.scanned_at,
       u.title, u.kb, u.classification, u.severity, u.is_driver, u.release_date, u.reboot_required, u.support_url,
       COALESCE(a.decision, '')::text AS decision,
       COALESCE(t.state, '')::text AS attempt_state, COALESCE(t.failures, 0)::int AS attempt_failures
FROM device_updates du
JOIN wu_updates u ON u.update_id = du.update_id AND u.org_id = @org_id::uuid
LEFT JOIN wu_approvals a ON a.org_id = u.org_id AND a.update_id = u.update_id
LEFT JOIN wu_attempts t ON t.update_id = du.update_id AND t.device_id = du.device_id
WHERE du.device_id = @device_id::uuid
ORDER BY CASE du.state WHEN 'pending_reboot' THEN 0 WHEN 'missing' THEN 1 WHEN 'downloaded' THEN 1 WHEN 'failed' THEN 2 ELSE 3 END,
         u.release_date DESC NULLS LAST, du.update_id;

-- name: GetDeviceWU :one
SELECT wu_rev, wu_scanned_at, wu_scan_error, wu_reboot_required, wu_policy, wu_service, wu_truncated FROM devices WHERE id = $1;

-- name: CountPolicyConflicts :many
-- Devices whose update policy is managed by something else (WSUS, deferrals, disabled automatic updates, service off).
-- With ignore_wsus on, a WSUS setting alone is not a conflict (WSUS is treated as not existing, D154).
SELECT d.id, d.hostname, d.wu_policy
FROM devices d
WHERE d.org_id = @org_id AND d.status = 'active' AND d.wu_policy IS NOT NULL
  AND ((NOT @ignore_wsus::boolean AND d.wu_policy->>'wsus_configured' = 'true') OR d.wu_policy->>'wufb_deferrals' = 'true'
       OR d.wu_policy->>'no_auto_update' = 'true' OR d.wu_policy->>'wu_service_disabled' = 'true')
ORDER BY lower(d.hostname)
LIMIT 500;

-- ---- decisions ----

-- name: UpsertApproval :exec
INSERT INTO wu_approvals (org_id, update_id, decision, source, rule_id, note, decided_by, decided_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now())
ON CONFLICT (org_id, update_id) DO UPDATE SET decision = EXCLUDED.decision, source = EXCLUDED.source, rule_id = EXCLUDED.rule_id,
    note = EXCLUDED.note, decided_by = EXCLUDED.decided_by, decided_at = now();

-- name: InsertRuleApproval :execrows
-- A rule never overrides an administrator's decision.
INSERT INTO wu_approvals (org_id, update_id, decision, source, rule_id, note, decided_at)
VALUES ($1, $2, 'approved', 'rule', $3, $4, now())
ON CONFLICT (org_id, update_id) DO NOTHING;

-- name: DeleteApproval :exec
DELETE FROM wu_approvals WHERE org_id = $1 AND update_id = $2;

-- name: GetApproval :one
SELECT * FROM wu_approvals WHERE org_id = $1 AND update_id = $2;

-- name: ListUnreviewedUpdates :many
SELECT u.* FROM wu_updates u
WHERE u.org_id = $1 AND NOT EXISTS (SELECT 1 FROM wu_approvals a WHERE a.org_id = u.org_id AND a.update_id = u.update_id)
ORDER BY u.release_date DESC NULLS LAST
LIMIT 5000;

-- name: ListOrgsWithUpdates :many
SELECT DISTINCT org_id FROM wu_updates;

-- ---- rules ----

-- name: ListRules :many
SELECT * FROM wu_rules WHERE org_id = $1 ORDER BY lower(name), id;

-- name: GetRule :one
SELECT * FROM wu_rules WHERE id = $1 AND org_id = $2;

-- name: InsertRule :exec
INSERT INTO wu_rules (id, org_id, name, classifications, severities, include_drivers, delay_days, enabled, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: UpdateRule :execrows
UPDATE wu_rules SET name = $3, classifications = $4, severities = $5, include_drivers = $6, delay_days = $7, enabled = $8, updated_at = now()
WHERE id = $1 AND org_id = $2;

-- name: DeleteRule :execrows
DELETE FROM wu_rules WHERE id = $1 AND org_id = $2;

-- ---- rings ----

-- name: ListRings :many
SELECT * FROM wu_rings WHERE org_id = $1 ORDER BY ordinal;

-- name: GetRing :one
SELECT * FROM wu_rings WHERE id = $1 AND org_id = $2;

-- name: InsertRing :exec
INSERT INTO wu_rings (id, org_id, name, ordinal, group_ids, delay_days, soak_hours, success_threshold, maint_window, reboot, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11);

-- name: UpdateRing :execrows
UPDATE wu_rings SET name = $3, ordinal = $4, group_ids = $5, delay_days = $6, soak_hours = $7, success_threshold = $8,
    maint_window = $9, reboot = $10, enabled = $11, updated_at = now()
WHERE id = $1 AND org_id = $2;

-- name: DeleteRing :execrows
DELETE FROM wu_rings WHERE id = $1 AND org_id = $2;

-- ---- scheduling ----

-- name: ListApprovedUpdates :many
SELECT u.update_id, u.revision, u.title, u.is_driver, u.release_date, a.decided_at
FROM wu_approvals a JOIN wu_updates u ON u.org_id = a.org_id AND u.update_id = a.update_id
WHERE a.org_id = $1 AND a.decision = 'approved'
ORDER BY a.decided_at, u.update_id;

-- name: ListMissingForDevices :many
SELECT du.device_id, du.update_id, du.revision
FROM device_updates du
WHERE du.device_id = ANY(@device_ids::uuid[]) AND du.update_id = ANY(@update_ids::uuid[]) AND du.state IN ('missing', 'downloaded');

-- name: ListActiveWUDevices :many
SELECT DISTINCT device_id FROM jobs
WHERE org_id = $1 AND type = 'wu_install' AND status IN ('queued', 'sent', 'accepted', 'waiting', 'running');

-- name: ListAttemptsForUpdates :many
SELECT update_id, device_id, ring_id, state, failures, created_at, finished_at
FROM wu_attempts WHERE org_id = $1 AND update_id = ANY(@update_ids::uuid[]);

-- name: UpsertAttemptQueued :exec
INSERT INTO wu_attempts (org_id, update_id, device_id, ring_id, job_id, state, failures, created_at)
VALUES (@org_id, @update_id, @device_id, @ring_id, @job_id, 'queued', 0, @at::timestamptz)
ON CONFLICT (update_id, device_id) DO UPDATE SET ring_id = EXCLUDED.ring_id, job_id = EXCLUDED.job_id, state = 'queued',
    created_at = EXCLUDED.created_at, finished_at = NULL;

-- name: SetAttemptResult :exec
INSERT INTO wu_attempts (org_id, update_id, device_id, ring_id, job_id, state, failures, hresult, created_at, finished_at)
VALUES (@org_id, @update_id, @device_id, NULL, @job_id, @state, CASE WHEN @state::text = 'failed' THEN 1 ELSE 0 END, @hresult, @at::timestamptz, @at::timestamptz)
ON CONFLICT (update_id, device_id) DO UPDATE SET job_id = EXCLUDED.job_id, state = EXCLUDED.state, hresult = EXCLUDED.hresult,
    failures = CASE WHEN EXCLUDED.state = 'failed' THEN wu_attempts.failures + 1 ELSE 0 END, finished_at = EXCLUDED.finished_at;

-- name: ListQueuedAttemptUpdates :many
SELECT update_id FROM wu_attempts WHERE job_id = $1 AND state = 'queued';

-- name: DeleteQueuedAttemptsOfJob :exec
DELETE FROM wu_attempts WHERE job_id = $1 AND state = 'queued';

-- name: ListHolds :many
SELECT h.id, h.update_id, h.ring_id, h.reason, h.created_at, r.name AS ring_name, u.title
FROM wu_holds h JOIN wu_rings r ON r.id = h.ring_id LEFT JOIN wu_updates u ON u.org_id = h.org_id AND u.update_id = h.update_id
WHERE h.org_id = $1 AND h.released_at IS NULL
ORDER BY h.created_at DESC;

-- name: ListAllHoldsForUpdates :many
SELECT update_id, ring_id, released_at FROM wu_holds WHERE org_id = $1 AND update_id = ANY(@update_ids::uuid[]);

-- name: InsertHold :execrows
INSERT INTO wu_holds (id, org_id, update_id, ring_id, reason)
SELECT $1, $2, $3, $4, $5
WHERE NOT EXISTS (SELECT 1 FROM wu_holds WHERE org_id = $2 AND update_id = $3 AND ring_id = $4);

-- name: ReleaseHold :execrows
UPDATE wu_holds SET released_at = now(), released_by = $3 WHERE id = $1 AND org_id = $2 AND released_at IS NULL;

-- name: ListDevicesNeedingWUSettings :many
SELECT d.id FROM devices d JOIN org_settings s ON s.org_id = d.org_id
WHERE d.org_id = $1 AND d.status = 'active' AND d.online AND d.wu_settings_rev < s.wu_rev
ORDER BY d.id LIMIT 200;

-- name: ListDevicesNeedingWUSettingsNoRow :many
SELECT d.id FROM devices d
WHERE d.org_id = $1 AND d.status = 'active' AND d.online AND d.wu_settings_rev < 1
  AND NOT EXISTS (SELECT 1 FROM org_settings s WHERE s.org_id = d.org_id)
ORDER BY d.id LIMIT 200;

-- name: SetDeviceWUSettingsRev :exec
UPDATE devices SET wu_settings_rev = $2 WHERE id = $1;

-- name: BumpWURev :exec
-- Makes every device get a scan with the current source settings (used when a setting that changes the source is saved).
INSERT INTO org_settings (org_id, wu_rev, updated_at) VALUES ($1, 2, now())
ON CONFLICT (org_id) DO UPDATE SET wu_rev = org_settings.wu_rev + 1, updated_at = now();

-- name: BumpWUSettings :exec
INSERT INTO org_settings (org_id, wu_service, wu_include_drivers, wu_rev, updated_at) VALUES ($1, $2, $3, 2, now())
ON CONFLICT (org_id) DO UPDATE SET wu_service = EXCLUDED.wu_service, wu_include_drivers = EXCLUDED.wu_include_drivers,
    wu_rev = org_settings.wu_rev + 1, updated_at = now();

-- name: ListActiveDeviceIDs :many
SELECT id, hostname, online FROM devices WHERE org_id = $1 AND status = 'active' AND id = ANY(@device_ids::uuid[]);

-- name: ListOrgIDs :many
SELECT id FROM organizations;

-- name: ListUpdateDeviceStates :many
SELECT du.device_id, du.state, d.online
FROM device_updates du JOIN devices d ON d.id = du.device_id
WHERE d.org_id = $1 AND du.update_id = $2 AND d.status = 'active'
LIMIT 20000;

-- name: ListDeviceUpdateIDs :many
SELECT update_id, revision FROM device_updates WHERE device_id = $1 AND state = ANY(@states::text[]);

-- name: LockDeviceJobType :exec
-- Serialises requests of one kind for one device (two clicks at once must find each other).
SELECT pg_advisory_xact_lock(hashtextextended(@lock_key::text, 0));

-- name: GetActiveJobOfType :one
-- A request of this kind that has not finished: a second click joins it instead of queueing another.
SELECT id FROM jobs
WHERE device_id = @device_id AND type = @type::text
  AND status IN ('queued', 'sent', 'accepted', 'waiting', 'running') AND expires_at > now()
ORDER BY created_at DESC LIMIT 1;
