-- name: InsertScript :exec
INSERT INTO scripts (id, org_id, name, description, interpreter, current_version, created_by) VALUES ($1, $2, $3, $4, $5, 1, $6);

-- name: UpdateScriptMeta :execrows
UPDATE scripts SET name = $3, description = $4, updated_at = now() WHERE id = $1 AND org_id = $2;

-- name: SetScriptVersion :execrows
UPDATE scripts SET current_version = $3, updated_at = now() WHERE id = $1 AND org_id = $2;

-- name: DeleteScript :execrows
DELETE FROM scripts WHERE id = $1 AND org_id = $2;

-- name: GetScript :one
SELECT * FROM scripts WHERE id = $1 AND org_id = $2;

-- name: ListScripts :many
SELECT s.*, (SELECT count(*) FROM script_runs r WHERE r.script_id = s.id)::bigint AS runs,
       (SELECT max(r.requested_at) FROM script_runs r WHERE r.script_id = s.id) AS last_run_at
FROM scripts s WHERE s.org_id = $1 ORDER BY lower(s.name);

-- name: InsertScriptVersion :exec
INSERT INTO script_versions (script_id, version, content, sha256, note, created_by) VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetScriptVersion :one
SELECT * FROM script_versions WHERE script_id = $1 AND version = $2;

-- name: ListScriptVersions :many
SELECT v.script_id, v.version, v.sha256, v.note, v.created_at, COALESCE(u.display_name, '') AS created_by_name
FROM script_versions v LEFT JOIN users u ON u.id = v.created_by
WHERE v.script_id = $1 ORDER BY v.version DESC;

-- name: InsertScriptRun :exec
INSERT INTO script_runs (id, org_id, script_id, script_name, version, interpreter, content, sha256, timeout_s, reason, target_group_ids, target_device_ids, status, requested_by, devices)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15);

-- name: GetScriptRun :one
SELECT * FROM script_runs WHERE id = $1 AND org_id = $2;

-- name: DecideScriptRun :execrows
UPDATE script_runs SET status = @status::text, decided_by = @decided_by, decided_at = @decided_at, decision_note = @note::text
WHERE id = @id AND org_id = @org_id AND status = 'pending_approval';

-- name: SetScriptRunStatus :execrows
UPDATE script_runs SET status = $3 WHERE id = $1 AND org_id = $2 AND status IN ('pending_approval', 'running');

-- name: ListScriptRuns :many
SELECT r.id, r.script_id, r.script_name, r.version, r.reason, r.status, r.requested_at, r.decided_at, r.devices, r.requested_by,
       COALESCE(u.display_name, '') AS requested_by_name, COALESCE(d.display_name, '') AS decided_by_name,
       (SELECT count(*) FROM jobs j WHERE j.script_run_id = r.id AND j.status = 'succeeded')::bigint AS succeeded,
       (SELECT count(*) FROM jobs j WHERE j.script_run_id = r.id AND j.status IN ('failed', 'expired', 'rejected'))::bigint AS failed
FROM script_runs r LEFT JOIN users u ON u.id = r.requested_by LEFT JOIN users d ON d.id = r.decided_by
WHERE r.org_id = $1 ORDER BY r.requested_at DESC LIMIT $2;

-- name: ListScriptRunJobs :many
SELECT j.id, j.device_id, d.hostname, j.status, j.status_reason, j.exit_code, j.finished_at, j.started_at,
       (o.job_id IS NOT NULL)::boolean AS has_output
FROM jobs j JOIN devices d ON d.id = j.device_id LEFT JOIN script_outputs o ON o.job_id = j.id
WHERE j.script_run_id = $1 ORDER BY lower(d.hostname), j.id;

-- name: CancelJobsOfScriptRun :many
UPDATE jobs SET status = 'cancelled', status_reason = 'run_cancelled', finished_at = $2
WHERE script_run_id = $1 AND status IN ('queued', 'sent', 'accepted', 'waiting')
RETURNING id, device_id;

-- name: InsertScriptOutput :exec
INSERT INTO script_outputs (job_id, run_id, exit_code, output) VALUES ($1, $2, $3, $4) ON CONFLICT (job_id) DO NOTHING;

-- name: PruneScriptOutputs :exec
DELETE FROM script_outputs WHERE created_at < $1;

-- name: GetScriptOutput :one
SELECT o.job_id, o.exit_code, o.output, o.created_at, j.device_id
FROM script_outputs o JOIN jobs j ON j.id = o.job_id
WHERE o.job_id = $1 AND o.run_id = $2 AND j.org_id = $3;

-- name: CountApprovers :one
SELECT count(DISTINCT u.id)::bigint FROM users u JOIN role_bindings b ON b.user_id = u.id
WHERE u.org_id = $1 AND u.id <> $2 AND u.status = 'active' AND b.role = 'admin' AND b.scope_type = 'org';
