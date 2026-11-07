-- +goose Up
-- Phase 5: user and site administration, scoped API tokens and WebAuthn security keys.

ALTER TABLE users
    ADD COLUMN must_change_password boolean NOT NULL DEFAULT false,
    ADD COLUMN created_by uuid REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX role_bindings_scope ON role_bindings (scope_type, scope_id);

-- Bearer tokens for automation. Only the SHA-256 of the secret is stored; the secret is shown once.
-- A token's power is the intersection of its scopes and its owner's CURRENT permissions.
CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations(id),
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    prefix       text NOT NULL,                       -- first characters of the secret, to recognise a token in lists
    token_hash   bytea NOT NULL UNIQUE,
    scopes       text[] NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 64),
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    last_used_ip text NOT NULL DEFAULT '',
    revoked_at   timestamptz
);
CREATE INDEX api_tokens_user ON api_tokens (user_id);

-- A security key or passkey used as a second factor.
CREATE TABLE webauthn_credentials (
    id            uuid PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    record        bytea NOT NULL,              -- the library's credential record (JSON: public key, flags, authenticator data)
    sign_count    bigint NOT NULL DEFAULT 0,
    name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials (user_id);

-- Challenge state between "begin" and "finish" of a WebAuthn ceremony (short-lived, single use).
CREATE TABLE webauthn_ceremonies (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       text NOT NULL CHECK (kind IN ('register', 'login')),
    data       bytea NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX webauthn_ceremonies_expiry ON webauthn_ceremonies (expires_at);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON api_tokens, webauthn_credentials, webauthn_ceremonies TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS webauthn_ceremonies, webauthn_credentials, api_tokens CASCADE;
DROP INDEX IF EXISTS role_bindings_scope;
ALTER TABLE users DROP COLUMN IF EXISTS must_change_password, DROP COLUMN IF EXISTS created_by;
