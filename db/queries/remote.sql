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

-- name: UpsertPeerContent :exec
INSERT INTO peer_content (device_id, sha256, seen_at) VALUES ($1, $2, $3)
ON CONFLICT (device_id, sha256) DO UPDATE SET seen_at = EXCLUDED.seen_at;

-- name: PrunePeerContent :exec
DELETE FROM peer_content WHERE seen_at < $1;

-- name: ListPeerCandidates :many
-- Online devices that share downloads and have installed from this file, newest first.
SELECT d.id, d.hostname, d.peer_port, d.hardware
FROM peer_content p JOIN devices d ON d.id = p.device_id
WHERE p.sha256 = $1 AND p.seen_at > $2 AND d.org_id = $3 AND d.id <> $4 AND d.status = 'active' AND d.online AND d.peer_port > 0
ORDER BY p.seen_at DESC LIMIT 60;
