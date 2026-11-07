-- +goose Up
-- Single sign-on with OpenID Connect (D128).

-- Where a role binding came from. 'sso' bindings follow the identity provider's groups or roles at every sign-in; 'local'
-- ones (everything an administrator set by hand, and everything that existed before) are never touched by single sign-on.
ALTER TABLE role_bindings ADD COLUMN source text NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'sso'));

-- One sign-in in progress: what the callback must match. Single use, ten minutes, never reused.
CREATE TABLE sso_flows (
    state_hash bytea PRIMARY KEY,           -- SHA-256 of the state value sent to the provider
    nonce      text NOT NULL,
    verifier   text NOT NULL,               -- PKCE code verifier
    binding_hash bytea NOT NULL,            -- SHA-256 of a value kept in a cookie of the browser that began the sign-in
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sso_flows_created ON sso_flows (created_at);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON sso_flows TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS sso_flows;
ALTER TABLE role_bindings DROP COLUMN IF EXISTS source;
