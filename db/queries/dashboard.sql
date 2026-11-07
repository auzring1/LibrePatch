-- Dashboard and notifications (decision D94). Every query takes site_ids: NULL means every site.

-- name: UpsertComplianceSnapshot :exec
INSERT INTO compliance_snapshots (org_id, site_id, taken_on, compliant, non_compliant, unknown, taken_at)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (org_id, site_id, taken_on) DO UPDATE
SET compliant = EXCLUDED.compliant, non_compliant = EXCLUDED.non_compliant, unknown = EXCLUDED.unknown, taken_at = EXCLUDED.taken_at;

-- name: ListComplianceHistory :many
SELECT taken_on, sum(compliant)::int AS compliant, sum(non_compliant)::int AS non_compliant, sum(unknown)::int AS unknown
FROM compliance_snapshots
WHERE org_id = @org_id AND taken_on >= @since::date
  AND (sqlc.narg('site_ids')::uuid[] IS NULL OR site_id = ANY(sqlc.narg('site_ids')::uuid[]))
GROUP BY taken_on ORDER BY taken_on;

-- name: PruneComplianceSnapshots :execrows
DELETE FROM compliance_snapshots WHERE taken_on < $1;

-- name: ListSnapshotOrgs :many
SELECT id FROM organizations;

-- name: CountFailedJobsSince :one
SELECT count(*)::bigint FROM jobs j JOIN devices d ON d.id = j.device_id
WHERE j.org_id = @org_id AND j.status = 'failed' AND COALESCE(j.finished_at, j.created_at) > @since::timestamptz
  AND (sqlc.narg('site_ids')::uuid[] IS NULL OR d.site_id = ANY(sqlc.narg('site_ids')::uuid[]));

-- name: ListFailedJobsSince :many
SELECT j.id, j.title, j.device_id, d.hostname, j.status_reason, COALESCE(j.finished_at, j.created_at)::timestamptz AS at
FROM jobs j JOIN devices d ON d.id = j.device_id
WHERE j.org_id = @org_id AND j.status = 'failed' AND COALESCE(j.finished_at, j.created_at) > @since::timestamptz
  AND (sqlc.narg('site_ids')::uuid[] IS NULL OR d.site_id = ANY(sqlc.narg('site_ids')::uuid[]))
ORDER BY COALESCE(j.finished_at, j.created_at) DESC LIMIT @row_limit::int;

-- name: TopMissingUpdates :many
SELECT u.update_id, u.title, u.severity, u.classification, u.kb, count(DISTINCT du.device_id)::int AS devices
FROM device_updates du
JOIN devices d ON d.id = du.device_id AND d.status = 'active'
JOIN wu_updates u ON u.org_id = d.org_id AND u.update_id = du.update_id
LEFT JOIN wu_approvals a ON a.org_id = d.org_id AND a.update_id = du.update_id
WHERE d.org_id = @org_id AND du.state IN ('missing', 'downloaded', 'failed') AND COALESCE(a.decision, '') <> 'declined'
  AND (sqlc.narg('site_ids')::uuid[] IS NULL OR d.site_id = ANY(sqlc.narg('site_ids')::uuid[]))
GROUP BY u.update_id, u.title, u.severity, u.classification, u.kb
ORDER BY (u.severity = 'Critical') DESC, (u.severity = 'Important') DESC, count(DISTINCT du.device_id) DESC, u.title
LIMIT @row_limit::int;

-- name: AgentVersionCounts :many
SELECT agent_version, count(*)::int AS devices FROM devices
WHERE org_id = @org_id AND status = 'active'
  AND (sqlc.narg('site_ids')::uuid[] IS NULL OR site_id = ANY(sqlc.narg('site_ids')::uuid[]))
GROUP BY agent_version ORDER BY count(*) DESC, agent_version;

-- name: OpenHoldCount :one
SELECT count(*)::bigint FROM wu_holds WHERE org_id = $1 AND released_at IS NULL;

-- name: CountDevicesByState :one
SELECT count(*) FILTER (WHERE status = 'active')::bigint AS active,
       count(*) FILTER (WHERE status = 'active' AND online)::bigint AS online,
       count(*) FILTER (WHERE status = 'pending')::bigint AS pending
FROM devices
WHERE org_id = @org_id AND (sqlc.narg('site_ids')::uuid[] IS NULL OR site_id = ANY(sqlc.narg('site_ids')::uuid[]));
