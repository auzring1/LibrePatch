-- name: CreateSession :exec
INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, idle_expires_at, abs_expires_at,
                      mfa_verified_at, ip, user_agent, csrf_token)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: GetSession :one
SELECT * FROM sessions WHERE id_hash = $1;

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = $2, idle_expires_at = $3 WHERE id_hash = $1;

-- name: IncrementSessionMFAFailures :one
UPDATE sessions SET mfa_failures = mfa_failures + 1 WHERE id_hash = $1 RETURNING mfa_failures;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id_hash = $1;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = $1;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions WHERE idle_expires_at < $1 OR abs_expires_at < $1;

-- name: SetSessionPendingTOTP :exec
UPDATE sessions SET pending_totp_enc = $2 WHERE id_hash = $1;
