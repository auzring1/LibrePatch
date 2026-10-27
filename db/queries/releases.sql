-- ---- agent releases and rollout ----

-- name: InsertAgentRelease :exec
INSERT INTO agent_releases (id, org_id, version, os, arch, sha256, size, manifest, signature, key_id, notes, uploaded_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);

-- name: ListAgentReleases :many
SELECT r.*, (SELECT count(*) FROM devices d WHERE d.org_id = r.org_id AND d.status = 'active' AND d.agent_version = r.version)::bigint AS devices_on
FROM agent_releases r WHERE r.org_id = $1 ORDER BY r.created_at DESC;

-- name: GetAgentRelease :one
SELECT * FROM agent_releases WHERE org_id = $1 AND id = $2;

-- name: SetAgentReleaseStatus :execrows
UPDATE agent_releases SET status = $3 WHERE org_id = $1 AND id = $2;

-- name: DeleteAgentRelease :execrows
DELETE FROM agent_releases AS r WHERE r.org_id = $1 AND r.id = $2
  AND NOT EXISTS (SELECT 1 FROM agent_rollout o WHERE o.release_id = r.id);

-- name: GetAgentRollout :one
SELECT * FROM agent_rollout WHERE org_id = $1;

-- name: UpsertAgentRollout :exec
INSERT INTO agent_rollout (org_id, release_id, pilot_group_ids, soak_hours, success_threshold, batch_per_tick, maint_window, paused, paused_reason, started_at, updated_by, auto_new_release, updated_at)
VALUES (@org_id, @release_id, @pilot_group_ids, @soak_hours, @success_threshold, @batch_per_tick, @maint_window, @paused, @paused_reason, @started_at, @updated_by, @auto_new_release, now())
ON CONFLICT (org_id) DO UPDATE SET release_id = EXCLUDED.release_id, pilot_group_ids = EXCLUDED.pilot_group_ids, soak_hours = EXCLUDED.soak_hours,
    success_threshold = EXCLUDED.success_threshold, batch_per_tick = EXCLUDED.batch_per_tick, maint_window = EXCLUDED.maint_window,
    paused = EXCLUDED.paused, paused_reason = EXCLUDED.paused_reason, started_at = EXCLUDED.started_at, updated_by = EXCLUDED.updated_by,
    auto_new_release = EXCLUDED.auto_new_release, updated_at = now();

-- name: SetAgentRolloutTarget :execrows
UPDATE agent_rollout SET release_id = $2, started_at = $3, updated_at = now() WHERE org_id = $1;

-- name: PauseAgentRollout :exec
UPDATE agent_rollout SET paused = true, paused_reason = $2, updated_at = now() WHERE org_id = $1;

-- name: ListActiveRollouts :many
SELECT * FROM agent_rollout WHERE release_id IS NOT NULL AND NOT paused;

-- name: ListAgentUpdateCandidates :many
SELECT d.id, d.agent_version, d.online, a.state AS attempt_state, a.failures AS attempt_failures, a.finished_at AS attempt_finished
FROM devices d
LEFT JOIN agent_attempts a ON a.device_id = d.id AND a.release_id = @release_id
WHERE d.org_id = @org_id AND d.status = 'active' AND d.agent_version <> @version
  AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.device_id = d.id AND j.type = 'agent_update'
                  AND j.status IN ('queued', 'sent', 'accepted', 'waiting', 'running'))
ORDER BY d.online DESC, d.id
LIMIT 20000;

-- name: UpsertAgentAttemptQueued :exec
INSERT INTO agent_attempts (device_id, release_id, org_id, job_id, pilot, state, created_at)
VALUES ($1, $2, $3, $4, $5, 'queued', $6)
ON CONFLICT (device_id, release_id) DO UPDATE SET job_id = EXCLUDED.job_id, pilot = EXCLUDED.pilot, state = 'queued', created_at = EXCLUDED.created_at, finished_at = NULL;

-- name: GetAgentAttemptByJob :one
SELECT * FROM agent_attempts WHERE job_id = $1;

-- name: FinishAgentAttempt :exec
UPDATE agent_attempts SET state = @state::text,
    failures = CASE WHEN @state::text = 'failed' THEN failures + 1 ELSE failures END,
    last_error = @last_error, finished_at = @at
WHERE device_id = @device_id AND release_id = @release_id;

-- name: DeleteQueuedAgentAttemptOfJob :exec
DELETE FROM agent_attempts WHERE job_id = $1 AND state = 'queued';

-- name: AgentPilotStats :one
SELECT count(*) FILTER (WHERE state = 'updated')::bigint AS updated,
       count(*) FILTER (WHERE state = 'failed')::bigint AS failed,
       count(*) FILTER (WHERE state = 'queued')::bigint AS queued,
       COALESCE(EXTRACT(EPOCH FROM max(finished_at) FILTER (WHERE state = 'updated')), 0)::bigint AS last_updated_unix
FROM agent_attempts WHERE release_id = $1 AND pilot;

-- name: AgentRolloutProgress :one
SELECT count(*) FILTER (WHERE state = 'updated')::bigint AS updated,
       count(*) FILTER (WHERE state = 'failed')::bigint AS failed,
       count(*) FILTER (WHERE state = 'queued')::bigint AS queued
FROM agent_attempts WHERE release_id = $1;

-- name: CountActiveDevices :one
SELECT count(*) FROM devices WHERE org_id = $1 AND status = 'active';

-- name: CountDevicesByAgentVersion :many
SELECT agent_version, count(*)::bigint AS devices, count(*) FILTER (WHERE online)::bigint AS online
FROM devices WHERE org_id = $1 AND status = 'active' GROUP BY agent_version ORDER BY agent_version;

-- name: CountReleaseBlobUses :one
-- Agent releases AND custom package uploads can share one content-addressed file.
SELECT (SELECT count(*) FROM agent_releases r WHERE r.org_id = sqlc.arg(org_id) AND r.sha256 = sqlc.arg(sha256))
     + (SELECT count(*) FROM content_blobs b WHERE b.org_id = sqlc.arg(org_id) AND b.sha256 = sqlc.arg(sha256)) AS uses;
