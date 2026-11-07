-- +goose Up
-- Phase 2: software inventory, device users, dynamic groups.
-- Forward-only in production (see docs/RUNBOOK.md).

CREATE TABLE software_titles (
    id                    uuid PRIMARY KEY,
    org_id                uuid NOT NULL REFERENCES organizations(id),
    normalized_name       text NOT NULL,
    normalized_publisher  text NOT NULL,
    display_name          text NOT NULL,
    display_publisher     text NOT NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, normalized_name, normalized_publisher)
);
CREATE INDEX software_titles_name ON software_titles (org_id, normalized_name text_pattern_ops);

CREATE TABLE software_installs (
    device_id              uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    source                 text NOT NULL CHECK (source IN ('reg64','reg32','hku','hku32','msi','appx','portable')),
    scope                  text NOT NULL CHECK (scope IN ('machine','user')),
    user_sid               text NOT NULL DEFAULT '',
    item_key               text NOT NULL,
    title_id               uuid NOT NULL REFERENCES software_titles(id),
    name                   text NOT NULL,
    version                text NOT NULL DEFAULT '',
    version_key            bytea,           -- NULL when the version is unknown (vercmp.Key)
    publisher              text NOT NULL DEFAULT '',
    install_date           text NOT NULL DEFAULT '',
    install_location       text NOT NULL DEFAULT '',
    uninstall_string       text NOT NULL DEFAULT '',
    quiet_uninstall_string text NOT NULL DEFAULT '',
    product_code           text NOT NULL DEFAULT '',
    system_component       boolean NOT NULL DEFAULT false,
    first_seen_at          timestamptz NOT NULL,
    last_seen_at           timestamptz NOT NULL,
    PRIMARY KEY (device_id, source, scope, user_sid, item_key),
    CHECK ((scope = 'machine' AND user_sid = '') OR (scope = 'user' AND user_sid <> ''))
);
CREATE INDEX software_installs_title_version ON software_installs (title_id, version_key);
CREATE INDEX software_installs_device ON software_installs (device_id);

CREATE TABLE software_history (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id    uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    title_id     uuid NOT NULL REFERENCES software_titles(id),
    name         text NOT NULL,
    scope        text NOT NULL,
    user_sid     text NOT NULL DEFAULT '',
    change       text NOT NULL CHECK (change IN ('added','removed','version')),
    old_version  text NOT NULL DEFAULT '',
    new_version  text NOT NULL DEFAULT '',
    observed_at  timestamptz NOT NULL
);
CREATE INDEX software_history_device ON software_history (device_id, id DESC);
CREATE INDEX software_history_time ON software_history (observed_at);

CREATE TABLE device_users (
    device_id     uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sid           text NOT NULL,
    username      text NOT NULL DEFAULT '',
    domain        text NOT NULL DEFAULT '',
    profile_path  text NOT NULL DEFAULT '',
    last_logon_at timestamptz,
    loaded        boolean NOT NULL DEFAULT false,
    is_admin      boolean NOT NULL DEFAULT false,
    PRIMARY KEY (device_id, sid)
);

ALTER TABLE devices
    ADD COLUMN software_rev bigint NOT NULL DEFAULT 0,
    ADD COLUMN users_rev bigint NOT NULL DEFAULT 0,
    ADD COLUMN software_updated_at timestamptz,
    ADD COLUMN software_count integer NOT NULL DEFAULT 0,
    ADD COLUMN inventory_truncated boolean NOT NULL DEFAULT false,
    -- Filterable hardware facts, derived from the agent's JSON snapshot.
    ADD COLUMN chassis text GENERATED ALWAYS AS (COALESCE(hardware->>'chassis', '')) STORED NOT NULL,
    ADD COLUMN manufacturer text GENERATED ALWAYS AS (COALESCE(hardware->>'manufacturer', '')) STORED NOT NULL,
    ADD COLUMN model text GENERATED ALWAYS AS (COALESCE(hardware->>'model', '')) STORED NOT NULL,
    ADD COLUMN ram_bytes bigint GENERATED ALWAYS AS (COALESCE(NULLIF(hardware->>'ram_bytes', '')::bigint, 0)) STORED NOT NULL,
    ADD COLUMN os_build_num integer GENERATED ALWAYS AS (COALESCE(NULLIF(hardware->>'os_build', '')::integer, 0)) STORED NOT NULL;
CREATE INDEX devices_chassis ON devices (org_id, chassis);

-- Dynamic groups: a typed filter tree (docs/DATA_MODEL.md), evaluated on demand.
CREATE TABLE groups (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations(id),
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
    filter      jsonb NOT NULL,
    created_by  uuid NOT NULL REFERENCES users(id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON
            software_titles, software_installs, software_history, device_users, groups
        TO librepatch_app;
        GRANT USAGE ON SEQUENCE software_history_id_seq TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS groups, device_users, software_history, software_installs, software_titles CASCADE;
ALTER TABLE devices
    DROP COLUMN IF EXISTS os_build_num, DROP COLUMN IF EXISTS ram_bytes, DROP COLUMN IF EXISTS model,
    DROP COLUMN IF EXISTS manufacturer, DROP COLUMN IF EXISTS chassis, DROP COLUMN IF EXISTS inventory_truncated,
    DROP COLUMN IF EXISTS software_count, DROP COLUMN IF EXISTS software_updated_at,
    DROP COLUMN IF EXISTS users_rev, DROP COLUMN IF EXISTS software_rev;
