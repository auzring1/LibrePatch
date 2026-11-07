-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: CreateOrganization :exec
INSERT INTO organizations (id, name) VALUES ($1, $2);

-- name: CreateSite :exec
INSERT INTO sites (id, org_id, name, timezone) VALUES ($1, $2, $3, $4);

-- name: GetOrganization :one
SELECT * FROM organizations WHERE id = $1;

-- name: GetDefaultSite :one
SELECT * FROM sites WHERE org_id = $1 ORDER BY created_at, id LIMIT 1;

-- name: CreateUser :exec
INSERT INTO users (id, org_id, email, display_name, password_hash)
VALUES ($1, $2, $3, $4, $5);

-- name: CreateUserIdentity :exec
INSERT INTO user_identities (id, user_id, provider, subject) VALUES ($1, $2, $3, $4);

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: SetUserLoginFailure :exec
UPDATE users SET failed_logins = $2, locked_until = $3 WHERE id = $1;

-- name: SetUserLoginSuccess :exec
UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = $2 WHERE id = $1;

-- name: CreateRoleBinding :exec
INSERT INTO role_bindings (id, user_id, role, scope_type, scope_id) VALUES ($1, $2, $3, $4, $5);

-- name: ListRoleBindingsForUser :many
SELECT * FROM role_bindings WHERE user_id = $1 ORDER BY role, scope_type, scope_id;

-- name: UpsertTOTP :exec
INSERT INTO mfa_totp (user_id, secret_enc, last_used_step, confirmed_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (user_id) DO UPDATE
SET secret_enc = EXCLUDED.secret_enc, last_used_step = EXCLUDED.last_used_step, confirmed_at = EXCLUDED.confirmed_at;

-- name: GetTOTP :one
SELECT * FROM mfa_totp WHERE user_id = $1;

-- name: ConsumeTOTPStep :execrows
-- Atomically accept a TOTP time step only if it is newer than the last one used (replay protection).
UPDATE mfa_totp SET last_used_step = $2 WHERE user_id = $1 AND last_used_step < $2;

-- name: DeleteTOTP :exec
DELETE FROM mfa_totp WHERE user_id = $1;

-- name: InsertRecoveryCode :exec
INSERT INTO mfa_recovery_codes (id, user_id, code_hash) VALUES ($1, $2, $3);

-- name: ListUnusedRecoveryCodes :many
SELECT * FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL;

-- name: UseRecoveryCode :execrows
UPDATE mfa_recovery_codes SET used_at = $2 WHERE id = $1 AND used_at IS NULL;

-- name: DeleteRecoveryCodes :exec
DELETE FROM mfa_recovery_codes WHERE user_id = $1;

-- name: UpsertSetupState :exec
INSERT INTO setup_state (id, totp_secret_enc) VALUES (1, $1)
ON CONFLICT (id) DO UPDATE SET totp_secret_enc = EXCLUDED.totp_secret_enc, created_at = now();

-- name: GetSetupState :one
SELECT * FROM setup_state WHERE id = 1;

-- name: DeleteSetupState :exec
DELETE FROM setup_state WHERE id = 1;
