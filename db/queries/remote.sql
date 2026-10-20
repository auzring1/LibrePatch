-- name: InsertDeviceView :exec
INSERT INTO device_views (job_id, org_id, device_id, kind, data) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (job_id) DO NOTHING;

-- name: PruneDeviceViews :exec
DELETE FROM device_views WHERE created_at < $1;

-- name: GetDeviceView :one
SELECT job_id, kind, data, created_at FROM device_views WHERE job_id = $1 AND org_id = $2 AND device_id = $3;

-- name: ListWakeHelpers :many
-- Online computers that could send a Wake-on-LAN packet for another one on the same network.
SELECT id, site_id, hostname, hardware FROM devices
WHERE org_id = $1 AND status = 'active' AND online AND id <> $2 AND hardware IS NOT NULL
ORDER BY lower(hostname), id;
