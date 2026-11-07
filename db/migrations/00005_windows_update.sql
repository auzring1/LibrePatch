-- +goose Up
-- Phase 4: Windows Update catalog, per-device update state, approvals, auto-approval rules, rings
-- and the install attempts that gate promotion between rings. Forward-only in production.

ALTER TABLE devices
    ADD COLUMN wu_rev             bigint NOT NULL DEFAULT 0,
    ADD COLUMN wu_scanned_at      timestamptz,
    ADD COLUMN wu_scan_error      text NOT NULL DEFAULT '',
    ADD COLUMN wu_reboot_required boolean NOT NULL DEFAULT false,
    ADD COLUMN wu_policy          jsonb,
    ADD COLUMN wu_service         integer NOT NULL DEFAULT 0,
    ADD COLUMN wu_truncated       boolean NOT NULL DEFAULT false,
    ADD COLUMN wu_settings_rev    integer NOT NULL DEFAULT 0;  -- the org setting revision this device was last sent

ALTER TABLE org_settings
    ADD COLUMN wu_service         text NOT NULL DEFAULT 'default' CHECK (wu_service IN ('default', 'windows_update', 'microsoft_update')),
    ADD COLUMN wu_include_drivers boolean NOT NULL DEFAULT false,
    ADD COLUMN wu_rev             integer NOT NULL DEFAULT 1;

ALTER TABLE jobs DROP CONSTRAINT jobs_type_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_type_check CHECK (type IN
    ('software_install', 'software_uninstall', 'software_update', 'inventory_full', 'wu_scan', 'wu_install', 'wu_hide', 'reboot'));

-- Every update any device of the organization has reported (latest revision seen).
CREATE TABLE wu_updates (
    org_id          uuid NOT NULL REFERENCES organizations(id),
    update_id       uuid NOT NULL,
    revision        integer NOT NULL DEFAULT 0,
    title           text NOT NULL,
    kb              text[] NOT NULL DEFAULT '{}',
    classification  text NOT NULL DEFAULT '',
    severity        text NOT NULL DEFAULT '',
    products        text[] NOT NULL DEFAULT '{}',
    is_driver       boolean NOT NULL DEFAULT false,
    driver_class    text NOT NULL DEFAULT '',
    driver_hwid     text NOT NULL DEFAULT '',
    driver_version  text NOT NULL DEFAULT '',
    release_date    timestamptz,
    support_url     text NOT NULL DEFAULT '',
    size_bytes      bigint NOT NULL DEFAULT 0,
    reboot_required boolean NOT NULL DEFAULT false,
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, update_id)
);
CREATE INDEX wu_updates_release ON wu_updates (org_id, release_date DESC NULLS LAST);

-- What each device's last scan said about it (a full replacement on every scan).
CREATE TABLE device_updates (
    device_id  uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    update_id  uuid NOT NULL,
    revision   integer NOT NULL DEFAULT 0,
    state      text NOT NULL CHECK (state IN ('missing', 'downloaded', 'hidden', 'pending_reboot', 'failed')),
    last_error text NOT NULL DEFAULT '',
    scanned_at timestamptz NOT NULL,
    PRIMARY KEY (device_id, update_id)
);
CREATE INDEX device_updates_update ON device_updates (update_id, state);

-- Administrator (or rule) decisions. No row = pending review.
CREATE TABLE wu_approvals (
    org_id     uuid NOT NULL REFERENCES organizations(id),
    update_id  uuid NOT NULL,
    decision   text NOT NULL CHECK (decision IN ('approved', 'declined', 'hidden')),
    source     text NOT NULL CHECK (source IN ('manual', 'rule')),
    rule_id    uuid,
    note       text NOT NULL DEFAULT '',
    decided_by uuid REFERENCES users(id),
    decided_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, update_id)
);

CREATE TABLE wu_rules (
    id              uuid PRIMARY KEY,
    org_id          uuid NOT NULL REFERENCES organizations(id),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    classifications text[] NOT NULL DEFAULT '{}',   -- empty = any
    severities      text[] NOT NULL DEFAULT '{}',   -- empty = any (unrated updates match only when empty)
    include_drivers boolean NOT NULL DEFAULT false,
    delay_days      integer NOT NULL DEFAULT 0 CHECK (delay_days BETWEEN 0 AND 365),
    enabled         boolean NOT NULL DEFAULT true,
    created_by      uuid REFERENCES users(id),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE wu_rings (
    id                uuid PRIMARY KEY,
    org_id            uuid NOT NULL REFERENCES organizations(id),
    name              text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    ordinal           integer NOT NULL CHECK (ordinal BETWEEN 1 AND 20),
    group_ids         uuid[] NOT NULL DEFAULT '{}',
    delay_days        integer NOT NULL DEFAULT 0 CHECK (delay_days BETWEEN 0 AND 365),   -- after approval
    soak_hours        integer NOT NULL DEFAULT 0 CHECK (soak_hours BETWEEN 0 AND 2160),  -- before the next ring opens
    success_threshold integer NOT NULL DEFAULT 90 CHECK (success_threshold BETWEEN 1 AND 100),
    maint_window      jsonb,
    reboot            jsonb NOT NULL DEFAULT '{"allow":"never"}',
    enabled           boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, ordinal),
    UNIQUE (org_id, name)
);

-- The latest installation attempt per device and update; promotion between rings reads these.
CREATE TABLE wu_attempts (
    org_id      uuid NOT NULL REFERENCES organizations(id),
    update_id   uuid NOT NULL,
    device_id   uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ring_id     uuid REFERENCES wu_rings(id) ON DELETE SET NULL,
    job_id      uuid REFERENCES jobs(id) ON DELETE SET NULL,
    state       text NOT NULL CHECK (state IN ('queued', 'installed', 'failed')),
    failures    integer NOT NULL DEFAULT 0,
    hresult     integer NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    PRIMARY KEY (update_id, device_id)
);
CREATE INDEX wu_attempts_ring ON wu_attempts (update_id, ring_id, state);
CREATE INDEX wu_attempts_job ON wu_attempts (job_id);

-- A ring that failed its success threshold stops the update from reaching later rings until released.
CREATE TABLE wu_holds (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations(id),
    update_id   uuid NOT NULL,
    ring_id     uuid NOT NULL REFERENCES wu_rings(id) ON DELETE CASCADE,  -- the ring whose result caused the hold
    reason      text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    released_at timestamptz,
    released_by uuid REFERENCES users(id)
);
CREATE UNIQUE INDEX wu_holds_open ON wu_holds (org_id, update_id, ring_id) WHERE released_at IS NULL;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON
            wu_updates, device_updates, wu_approvals, wu_rules, wu_rings, wu_attempts, wu_holds
        TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS wu_holds, wu_attempts, wu_rings, wu_rules, wu_approvals, device_updates, wu_updates CASCADE;
ALTER TABLE jobs DROP CONSTRAINT jobs_type_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_type_check CHECK (type IN ('software_install', 'software_uninstall', 'software_update', 'inventory_full'));
ALTER TABLE org_settings DROP COLUMN IF EXISTS wu_service, DROP COLUMN IF EXISTS wu_include_drivers, DROP COLUMN IF EXISTS wu_rev;
ALTER TABLE devices DROP COLUMN IF EXISTS wu_rev, DROP COLUMN IF EXISTS wu_scanned_at, DROP COLUMN IF EXISTS wu_scan_error,
    DROP COLUMN IF EXISTS wu_reboot_required, DROP COLUMN IF EXISTS wu_policy, DROP COLUMN IF EXISTS wu_service, DROP COLUMN IF EXISTS wu_truncated, DROP COLUMN IF EXISTS wu_settings_rev;
