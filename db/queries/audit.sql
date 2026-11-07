-- name: LockAuditChain :exec
SELECT pg_advisory_xact_lock(7231001);

-- name: GetLastAuditHash :one
SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1;

-- name: InsertAudit :one
INSERT INTO audit_log (ts, org_id, actor_type, actor_id, actor_ip, action, target_type, target_ids,
                       outcome, details, prev_hash, hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING id;

-- name: ListAudit :many
SELECT * FROM audit_log
WHERE org_id = $1 AND (sqlc.narg('before_id')::bigint IS NULL OR id < sqlc.narg('before_id')::bigint)
  AND (sqlc.narg('action_prefix')::text IS NULL OR action LIKE sqlc.narg('action_prefix')::text || '%')
  AND (sqlc.narg('outcome')::text IS NULL OR outcome = sqlc.narg('outcome')::text)
  AND (sqlc.narg('actor_type')::text IS NULL OR actor_type = sqlc.narg('actor_type')::text)
  AND (sqlc.narg('actor')::text IS NULL OR actor_id = sqlc.narg('actor')::text OR actor_ip = sqlc.narg('actor')::text)
  AND (sqlc.narg('target')::text IS NULL OR sqlc.narg('target')::text = ANY(target_ids))
  AND (sqlc.narg('from_ts')::timestamptz IS NULL OR ts >= sqlc.narg('from_ts')::timestamptz)
  AND (sqlc.narg('to_ts')::timestamptz IS NULL OR ts < sqlc.narg('to_ts')::timestamptz)
ORDER BY id DESC LIMIT $2;

-- name: ListAuditAscending :many
SELECT * FROM audit_log WHERE id > $1 ORDER BY id LIMIT $2;
