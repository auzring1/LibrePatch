-- name: InsertSSOFlow :exec
INSERT INTO sso_flows (state_hash, nonce, verifier, binding_hash) VALUES ($1, $2, $3, $4);

-- name: TakeSSOFlow :one
DELETE FROM sso_flows WHERE state_hash = $1 AND created_at > $2 RETURNING nonce, verifier, binding_hash;

-- name: PruneSSOFlows :exec
DELETE FROM sso_flows WHERE created_at < $1;

-- name: GetUserByIdentity :one
SELECT u.* FROM users u JOIN user_identities i ON i.user_id = u.id WHERE i.provider = $1 AND i.subject = $2;

-- name: ListSSOBindings :many
SELECT * FROM role_bindings WHERE user_id = $1 AND source = 'sso';

-- name: CreateSSOBinding :exec
INSERT INTO role_bindings (id, user_id, role, scope_type, scope_id, source) VALUES ($1, $2, $3, 'org', $4, 'sso')
ON CONFLICT (user_id, role, scope_type, scope_id) DO NOTHING;

-- name: DeleteSSOBinding :execrows
DELETE FROM role_bindings WHERE id = $1 AND user_id = $2 AND source = 'sso';

-- name: UserHasIdentity :one
SELECT EXISTS (SELECT 1 FROM user_identities WHERE user_id = $1 AND provider = $2);

-- name: ListSSOUsers :many
SELECT user_id FROM user_identities WHERE provider = $1;
