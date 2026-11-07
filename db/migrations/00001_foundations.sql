-- +goose Up
-- Phase 1 foundations. See docs/DATA_MODEL.md.
-- Runs as the schema owner (librepatch_owner). Runtime uses librepatch_app (DML only).

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE organizations (
    id          uuid PRIMARY KEY,
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sites (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations(id),
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    timezone    text NOT NULL DEFAULT 'UTC',
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE users (
    id                  uuid PRIMARY KEY,
    org_id              uuid NOT NULL REFERENCES organizations(id),
    email               citext NOT NULL UNIQUE CHECK (length(email) BETWEEN 3 AND 254),
    display_name        text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
    password_hash       text NOT NULL,
    status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    failed_logins       integer NOT NULL DEFAULT 0,
    locked_until        timestamptz,
    password_changed_at timestamptz NOT NULL DEFAULT now(),
    last_login_at       timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now()
);

-- OIDC-ready: local accounts get a ('local', user_id) identity; SSO adds more later.
CREATE TABLE user_identities (
    id        uuid PRIMARY KEY,
    user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider  text NOT NULL,
    subject   text NOT NULL,
    UNIQUE (provider, subject)
);

CREATE TABLE mfa_totp (
    user_id         uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc      bytea NOT NULL,            -- AES-256-GCM under the server KEK
    last_used_step  bigint NOT NULL DEFAULT 0, -- replay protection
    confirmed_at    timestamptz NOT NULL
);

CREATE TABLE mfa_recovery_codes (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL,
    used_at    timestamptz
);
CREATE INDEX mfa_recovery_codes_user ON mfa_recovery_codes (user_id);

CREATE TABLE role_bindings (
    id          uuid PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        text NOT NULL CHECK (role IN ('admin', 'operator', 'readonly')),
    scope_type  text NOT NULL CHECK (scope_type IN ('org', 'site')),
    scope_id    uuid NOT NULL,
    UNIQUE (user_id, role, scope_type, scope_id)
);

CREATE TABLE sessions (
    id_hash          bytea PRIMARY KEY,         -- SHA-256 of the cookie value
    user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at       timestamptz NOT NULL,
    last_seen_at     timestamptz NOT NULL,
    idle_expires_at  timestamptz NOT NULL,
    abs_expires_at   timestamptz NOT NULL,
    mfa_verified_at  timestamptz,
    mfa_failures     integer NOT NULL DEFAULT 0,
    -- TOTP secret offered to a user who must (re-)enroll MFA, sealed with the KEK.
    pending_totp_enc bytea,
    ip               text NOT NULL DEFAULT '',
    user_agent       text NOT NULL DEFAULT '',
    csrf_token       text NOT NULL
);
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_abs_expiry ON sessions (abs_expires_at);

-- Pending first-run state (TOTP secret shown to the admin before setup completes).
CREATE TABLE setup_state (
    id               integer PRIMARY KEY CHECK (id = 1),
    totp_secret_enc  bytea NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE pki_material (
    id              uuid PRIMARY KEY,
    kind            text NOT NULL CHECK (kind IN ('root', 'issuing', 'job_signing', 'gateway')),
    cert_der        bytea NOT NULL,
    key_enc         bytea NOT NULL,
    key_protection  text NOT NULL CHECK (key_protection IN ('kek', 'passphrase')),
    not_after       timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    retired_at      timestamptz
);
CREATE UNIQUE INDEX pki_material_active_kind ON pki_material (kind) WHERE retired_at IS NULL;

CREATE TABLE enrollment_tokens (
    id                uuid PRIMARY KEY,
    org_id            uuid NOT NULL REFERENCES organizations(id),
    site_id           uuid NOT NULL REFERENCES sites(id),
    name              text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    token_hash        bytea NOT NULL UNIQUE,
    max_uses          integer NOT NULL CHECK (max_uses BETWEEN 1 AND 100000),
    used_count        integer NOT NULL DEFAULT 0,
    expires_at        timestamptz NOT NULL,
    require_approval  boolean NOT NULL,
    created_by        uuid NOT NULL REFERENCES users(id),
    created_at        timestamptz NOT NULL DEFAULT now(),
    revoked_at        timestamptz
);
CREATE INDEX enrollment_tokens_org ON enrollment_tokens (org_id, created_at DESC);

CREATE TABLE devices (
    id                   uuid PRIMARY KEY,
    org_id               uuid NOT NULL REFERENCES organizations(id),
    site_id              uuid NOT NULL REFERENCES sites(id),
    status               text NOT NULL CHECK (status IN ('pending', 'active', 'revoked', 'retired')),
    status_reason        text NOT NULL DEFAULT '',
    hostname             text NOT NULL,
    smbios_uuid          text NOT NULL DEFAULT '',
    serial               text NOT NULL DEFAULT '',
    os_caption           text NOT NULL DEFAULT '',
    os_build             text NOT NULL DEFAULT '',
    arch                 text NOT NULL DEFAULT '',
    agent_version        text NOT NULL DEFAULT '',
    enrolled_via         uuid REFERENCES enrollment_tokens(id),
    replaces_device_id   uuid REFERENCES devices(id),
    enroll_ticket_hash   bytea UNIQUE,
    pending_csr          bytea,
    enrolled_at          timestamptz NOT NULL DEFAULT now(),
    approved_by          uuid REFERENCES users(id),
    approved_at          timestamptz,
    revoked_by           uuid REFERENCES users(id),
    revoked_at           timestamptz,
    last_seen_at         timestamptz,
    online               boolean NOT NULL DEFAULT false,
    last_ip              text NOT NULL DEFAULT '',
    hardware             jsonb,
    hardware_rev         bigint NOT NULL DEFAULT 0,
    hardware_updated_at  timestamptz,
    uptime_s             bigint NOT NULL DEFAULT 0,
    pending_reboot       boolean NOT NULL DEFAULT false,
    logged_on_user       text NOT NULL DEFAULT ''
);
CREATE INDEX devices_org_status ON devices (org_id, status);
CREATE INDEX devices_hw_identity ON devices (org_id, smbios_uuid, serial);

CREATE TABLE device_certs (
    serial             text PRIMARY KEY,        -- lowercase hex
    device_id          uuid NOT NULL REFERENCES devices(id),
    public_key_sha256  bytea NOT NULL,
    not_before         timestamptz NOT NULL,
    not_after          timestamptz NOT NULL,
    issued_at          timestamptz NOT NULL DEFAULT now(),
    revoked_at         timestamptz,
    revoke_reason      text NOT NULL DEFAULT ''
);
CREATE INDEX device_certs_device ON device_certs (device_id);

-- Append-only, hash-chained audit log (docs/THREAT-MODEL.md T-SRV-4).
CREATE TABLE audit_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts          timestamptz NOT NULL,
    org_id      uuid,
    actor_type  text NOT NULL CHECK (actor_type IN ('user', 'api_token', 'system', 'device', 'anonymous')),
    actor_id    text NOT NULL DEFAULT '',
    actor_ip    text NOT NULL DEFAULT '',
    action      text NOT NULL,
    target_type text NOT NULL DEFAULT '',
    target_ids  text[] NOT NULL DEFAULT '{}',
    outcome     text NOT NULL CHECK (outcome IN ('success', 'denied', 'error')),
    details     jsonb NOT NULL DEFAULT '{}',
    prev_hash   bytea NOT NULL,
    hash        bytea NOT NULL
);
CREATE INDEX audit_log_org_ts ON audit_log (org_id, id DESC);

-- +goose StatementBegin
CREATE FUNCTION audit_log_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

-- Least-privilege runtime role. Created by deploy/postgres/init (or the test
-- harness); if it does not exist (single-user dev database) grants are skipped
-- and the server logs a warning at startup.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT USAGE ON SCHEMA public TO librepatch_app;
        GRANT SELECT, INSERT, UPDATE, DELETE ON
            organizations, sites, users, user_identities, mfa_totp, mfa_recovery_codes,
            role_bindings, sessions, setup_state, pki_material, enrollment_tokens,
            devices, device_certs
        TO librepatch_app;
        GRANT SELECT, INSERT ON audit_log TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
-- Forward-only in production (RUNBOOK). Down exists for local development only.
DROP TABLE IF EXISTS audit_log, device_certs, devices, enrollment_tokens, pki_material,
    setup_state, sessions, role_bindings, mfa_recovery_codes, mfa_totp, user_identities,
    users, sites, organizations CASCADE;
DROP FUNCTION IF EXISTS audit_log_immutable();
