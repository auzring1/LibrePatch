-- +goose Up
-- Phase 5: agent self-update. Vendor-signed releases uploaded by an administrator, one rollout
-- setting per organization, and the per-device attempts that gate promotion beyond the pilot.

ALTER TABLE jobs DROP CONSTRAINT jobs_type_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_type_check CHECK (type IN
    ('software_install', 'software_uninstall', 'software_update', 'inventory_full', 'wu_scan', 'wu_install', 'wu_hide', 'reboot', 'agent_update'));

CREATE TABLE agent_releases (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations(id),
    version     text NOT NULL,
    os          text NOT NULL CHECK (os IN ('windows', 'linux')),
    arch        text NOT NULL CHECK (arch IN ('amd64', 'arm64')),
    sha256      bytea NOT NULL CHECK (length(sha256) = 32),
    size        bigint NOT NULL CHECK (size > 0),
    manifest    bytea NOT NULL,            -- the exact bytes the vendor signed
    signature   bytea NOT NULL,
    key_id      text NOT NULL,
    notes       text NOT NULL DEFAULT '',
    status      text NOT NULL DEFAULT 'available' CHECK (status IN ('available', 'withdrawn')),
    uploaded_by uuid REFERENCES users(id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, version, os, arch)
);

-- At most one row per organization: which release devices should converge on, and how.
CREATE TABLE agent_rollout (
    org_id            uuid PRIMARY KEY REFERENCES organizations(id),
    release_id        uuid REFERENCES agent_releases(id) ON DELETE SET NULL,
    pilot_group_ids   uuid[] NOT NULL DEFAULT '{}',       -- empty = no pilot, everyone at once
    soak_hours        integer NOT NULL DEFAULT 24 CHECK (soak_hours BETWEEN 0 AND 720),
    success_threshold integer NOT NULL DEFAULT 90 CHECK (success_threshold BETWEEN 1 AND 100),
    batch_per_tick    integer NOT NULL DEFAULT 100 CHECK (batch_per_tick BETWEEN 1 AND 1000),
    maint_window      jsonb,
    paused            boolean NOT NULL DEFAULT false,
    paused_reason     text NOT NULL DEFAULT '',
    started_at        timestamptz,
    updated_by        uuid REFERENCES users(id),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent_attempts (
    device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    release_id  uuid NOT NULL REFERENCES agent_releases(id) ON DELETE CASCADE,
    org_id      uuid NOT NULL REFERENCES organizations(id),
    job_id      uuid REFERENCES jobs(id) ON DELETE SET NULL,
    pilot       boolean NOT NULL DEFAULT false,
    state       text NOT NULL CHECK (state IN ('queued', 'updated', 'failed')),
    failures    integer NOT NULL DEFAULT 0,
    last_error  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    PRIMARY KEY (device_id, release_id)
);
CREATE INDEX agent_attempts_release ON agent_attempts (release_id, state);
CREATE INDEX agent_attempts_job ON agent_attempts (job_id);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON agent_releases, agent_rollout, agent_attempts TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS agent_attempts, agent_rollout, agent_releases CASCADE;
ALTER TABLE jobs DROP CONSTRAINT jobs_type_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_type_check CHECK (type IN
    ('software_install', 'software_uninstall', 'software_update', 'inventory_full', 'wu_scan', 'wu_install', 'wu_hide', 'reboot'));
