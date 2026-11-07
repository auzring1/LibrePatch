-- ---- users and role bindings ----

-- name: ListUsersInOrg :many
SELECT id, org_id, email, display_name, status, locked_until, last_login_at, created_at, must_change_password,
       EXISTS (SELECT 1 FROM mfa_totp t WHERE t.user_id = users.id) AS has_totp,
       (SELECT count(*) FROM webauthn_credentials w WHERE w.user_id = users.id)::int AS webauthn_count
FROM users WHERE org_id = $1 ORDER BY lower(display_name), email;

-- name: GetUserInOrg :one
SELECT * FROM users WHERE id = $1 AND org_id = $2;

-- name: CreateManagedUser :exec
INSERT INTO users (id, org_id, email, display_name, password_hash, must_change_password, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: UpdateUserProfile :execrows
UPDATE users SET display_name = $3, status = $4 WHERE id = $1 AND org_id = $2;

-- name: SetUserPassword :exec
UPDATE users SET password_hash = $2, must_change_password = $3, password_changed_at = $4, failed_logins = 0, locked_until = NULL WHERE id = $1;

-- name: DeleteUserInOrg :execrows
DELETE FROM users WHERE id = $1 AND org_id = $2;

-- name: ListRoleBindingsInOrg :many
SELECT b.id, b.user_id, b.role, b.scope_type, b.scope_id, b.source
FROM role_bindings b JOIN users u ON u.id = b.user_id WHERE u.org_id = $1
ORDER BY b.user_id, b.role, b.scope_type, b.scope_id;

-- name: DeleteRoleBinding :execrows
DELETE FROM role_bindings WHERE id = $1 AND user_id = $2;

-- name: CountOtherActiveOrgAdmins :one
SELECT count(DISTINCT u.id) FROM users u JOIN role_bindings b ON b.user_id = u.id
WHERE u.org_id = $1 AND u.status = 'active' AND b.role = 'admin' AND b.scope_type = 'org' AND u.id <> $2;

-- name: DeleteSessionsForUser :exec
DELETE FROM sessions WHERE user_id = $1;

-- ---- sites ----

-- name: ListSitesWithCounts :many
SELECT s.id, s.org_id, s.name, s.timezone, s.created_at,
       (SELECT count(*) FROM devices d WHERE d.site_id = s.id)::bigint AS devices
FROM sites s WHERE s.org_id = $1 ORDER BY s.name;

-- name: GetSiteInOrg :one
SELECT * FROM sites WHERE id = $1 AND org_id = $2;

-- name: UpdateSite :execrows
UPDATE sites SET name = $3, timezone = $4 WHERE id = $1 AND org_id = $2;

-- name: CountSiteDevices :one
SELECT count(*) FROM devices WHERE site_id = $1;

-- name: CountSiteTokens :one
SELECT count(*) FROM enrollment_tokens WHERE site_id = $1;

-- name: DeleteSite :execrows
DELETE FROM sites WHERE id = $1 AND org_id = $2;

-- name: DeleteBindingsForSite :exec
DELETE FROM role_bindings WHERE scope_type = 'site' AND scope_id = $1;

-- ---- WebAuthn ----

-- name: ListWebAuthnCredentials :many
SELECT * FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at;

-- name: InsertWebAuthnCredential :exec
INSERT INTO webauthn_credentials (id, user_id, credential_id, record, sign_count, name) VALUES ($1, $2, $3, $4, $5, $6);

-- name: UpdateWebAuthnCredentialUsage :exec
UPDATE webauthn_credentials SET record = $3, sign_count = $4, last_used_at = $5 WHERE user_id = $1 AND credential_id = $2;

-- name: DeleteWebAuthnCredential :execrows
DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2;

-- name: DeleteWebAuthnCredentialsForUser :exec
DELETE FROM webauthn_credentials WHERE user_id = $1;

-- name: InsertWebAuthnCeremony :exec
INSERT INTO webauthn_ceremonies (id, user_id, kind, data, expires_at) VALUES ($1, $2, $3, $4, $5);

-- name: TakeWebAuthnCeremony :one
DELETE FROM webauthn_ceremonies WHERE id = $1 AND user_id = $2 AND kind = $3 AND expires_at > $4 RETURNING data;

-- name: DeleteExpiredWebAuthnCeremonies :exec
DELETE FROM webauthn_ceremonies WHERE expires_at < $1;

-- ---- API tokens ----

-- name: InsertAPIToken :exec
INSERT INTO api_tokens (id, org_id, user_id, name, prefix, token_hash, scopes, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: ListAPITokensForUser :many
SELECT id, org_id, user_id, name, prefix, scopes, created_at, expires_at, last_used_at, last_used_ip, revoked_at
FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC;

-- name: ListAPITokensInOrg :many
SELECT t.id, t.org_id, t.user_id, t.name, t.prefix, t.scopes, t.created_at, t.expires_at, t.last_used_at, t.last_used_ip, t.revoked_at,
       u.email AS owner_email
FROM api_tokens t JOIN users u ON u.id = t.user_id WHERE t.org_id = $1 ORDER BY t.created_at DESC;

-- name: GetAPITokenByHash :one
SELECT * FROM api_tokens WHERE token_hash = $1;

-- name: TouchAPIToken :exec
UPDATE api_tokens SET last_used_at = $2, last_used_ip = $3 WHERE id = $1;

-- name: RevokeAPIToken :execrows
UPDATE api_tokens SET revoked_at = $3 WHERE id = $1 AND org_id = $2 AND revoked_at IS NULL;

-- name: RevokeAPITokensForUser :exec
UPDATE api_tokens SET revoked_at = $2 WHERE user_id = $1 AND revoked_at IS NULL;

-- name: CountActiveAPITokensForUser :one
SELECT count(*) FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now();

-- name: DeleteOtherSessionsForUser :exec
DELETE FROM sessions WHERE user_id = $1 AND id_hash <> $2;
