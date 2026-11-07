-- +goose Up
-- Phase 3: static groups, software catalog, content, deployments and jobs.
-- Forward-only in production (see docs/RUNBOOK.md).

-- Static groups: explicit device membership next to the dynamic (filter) kind.
ALTER TABLE groups
    ADD COLUMN kind text NOT NULL DEFAULT 'dynamic' CHECK (kind IN ('dynamic', 'static')),
    ALTER COLUMN filter DROP NOT NULL,
    ADD CONSTRAINT groups_kind_filter CHECK ((kind = 'dynamic' AND filter IS NOT NULL) OR kind = 'static');

CREATE TABLE group_members (
    group_id  uuid NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    added_by  uuid REFERENCES users(id),
    added_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, device_id)
);
CREATE INDEX group_members_device ON group_members (device_id);

-- Catalog: metadata for packages an admin imported or uploaded.
CREATE TABLE catalog_packages (
    id             uuid PRIMARY KEY,
    org_id         uuid NOT NULL REFERENCES organizations(id),
    source         text NOT NULL CHECK (source IN ('winget', 'custom')),
    identifier     text NOT NULL CHECK (length(identifier) BETWEEN 1 AND 200),
    name           text NOT NULL,
    publisher      text NOT NULL DEFAULT '',
    homepage       text NOT NULL DEFAULT '',
    license        text NOT NULL DEFAULT '',
    description    text NOT NULL DEFAULT '',
    verified       boolean NOT NULL DEFAULT false,        -- passed the VM matrix (signed overlay)
    self_updating  boolean NOT NULL DEFAULT false,
    imported_at    timestamptz NOT NULL DEFAULT now(),
    imported_by    uuid REFERENCES users(id),
    UNIQUE (org_id, source, identifier)
);

CREATE TABLE catalog_versions (
    id               uuid PRIMARY KEY,
    package_id       uuid NOT NULL REFERENCES catalog_packages(id) ON DELETE CASCADE,
    version          text NOT NULL,
    version_key      bytea,
    manifest_sha256  bytea,                                -- hash of the manifest text as imported
    imported_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (package_id, version)
);

CREATE TABLE catalog_installers (
    id                     uuid PRIMARY KEY,
    version_id             uuid NOT NULL REFERENCES catalog_versions(id) ON DELETE CASCADE,
    architecture           text NOT NULL CHECK (architecture IN ('x64', 'x86', 'arm64', 'neutral')),
    scope                  text NOT NULL CHECK (scope IN ('machine', 'user', 'any')),
    installer_type         text NOT NULL CHECK (installer_type IN ('msi', 'msix', 'inno', 'nsis', 'burn', 'exe', 'portable', 'zip')),
    nested_type            text NOT NULL DEFAULT '',
    nested_path            text NOT NULL DEFAULT '',
    url                    text NOT NULL DEFAULT '',        -- vendor URL ('' for uploaded content)
    sha256                 bytea NOT NULL CHECK (length(sha256) = 32),
    size                   bigint NOT NULL DEFAULT 0,
    file_name              text NOT NULL DEFAULT '',
    signer_subject         text NOT NULL DEFAULT '',        -- pinned signer (informational pin shown in the console)
    product_code           text NOT NULL DEFAULT '',
    upgrade_code           text NOT NULL DEFAULT '',
    switches               jsonb NOT NULL DEFAULT '{}',     -- {silent:[], custom:[]} from the manifest
    success_codes          integer[] NOT NULL DEFAULT '{}',
    expected_codes         integer[] NOT NULL DEFAULT '{}',
    min_os                 text NOT NULL DEFAULT '',
    detection              jsonb NOT NULL DEFAULT '[]',     -- generated or admin-defined rules
    uses_content_blob      boolean NOT NULL DEFAULT false,  -- served by the gateway from content_blobs
    unsupported            text NOT NULL DEFAULT ''         -- why this installer cannot be deployed ('' = deployable)
);
CREATE INDEX catalog_installers_version ON catalog_installers (version_id);

-- Per-organization overrides of a package.
CREATE TABLE package_overrides (
    org_id            uuid NOT NULL REFERENCES organizations(id),
    package_id        uuid NOT NULL REFERENCES catalog_packages(id) ON DELETE CASCADE,
    silent_args       text[] NOT NULL DEFAULT '{}',
    extra_detection   jsonb NOT NULL DEFAULT '[]',
    pin               text NOT NULL DEFAULT '',             -- '' | 'latest' | '= x' | '< x'
    excluded          boolean NOT NULL DEFAULT false,
    user_scope_policy text NOT NULL DEFAULT '' CHECK (user_scope_policy IN ('', 'report_only', 'update_in_place', 'convert_to_machine', 'remove')),
    self_update_policy text NOT NULL DEFAULT '' CHECK (self_update_policy IN ('', 'defer_to_vendor', 'enforce')),
    updated_by        uuid REFERENCES users(id),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, package_id)
);

CREATE TABLE org_settings (
    org_id            uuid PRIMARY KEY REFERENCES organizations(id),
    user_scope_policy text NOT NULL DEFAULT 'report_only' CHECK (user_scope_policy IN ('report_only', 'update_in_place', 'convert_to_machine', 'remove')),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- Custom package content, addressed by SHA-256, stored on the content volume.
CREATE TABLE content_blobs (
    org_id       uuid NOT NULL REFERENCES organizations(id),
    sha256       bytea NOT NULL CHECK (length(sha256) = 32),
    size         bigint NOT NULL,
    file_name    text NOT NULL,
    uploaded_by  uuid REFERENCES users(id),
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, sha256)
);

-- Deployments and jobs.
CREATE TABLE deployments (
    id                 uuid PRIMARY KEY,
    org_id             uuid NOT NULL REFERENCES organizations(id),
    name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    action             text NOT NULL CHECK (action IN ('install', 'update', 'uninstall')),
    package_id         uuid NOT NULL REFERENCES catalog_packages(id),
    version_id         uuid REFERENCES catalog_versions(id),   -- null for uninstall
    scope              text NOT NULL CHECK (scope IN ('machine', 'user')),
    target_group_ids   uuid[] NOT NULL DEFAULT '{}',
    target_device_ids  uuid[] NOT NULL DEFAULT '{}',
    starts_at          timestamptz NOT NULL,                   -- jobs carry this as not_before
    expires_at         timestamptz NOT NULL,                   -- jobs expire here
    maint_window       jsonb,                                  -- maintenance window evaluated on the device
    unverified_confirmed boolean NOT NULL DEFAULT false,       -- admin confirmed deploying an unverified package
    status             text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'paused', 'completed', 'cancelled')),
    created_by         uuid NOT NULL REFERENCES users(id),
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX deployments_org ON deployments (org_id, created_at DESC);

CREATE TABLE jobs (
    id            uuid PRIMARY KEY,
    org_id        uuid NOT NULL REFERENCES organizations(id),
    deployment_id uuid REFERENCES deployments(id) ON DELETE SET NULL,
    device_id     uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    user_sid      text NOT NULL DEFAULT '',
    type          text NOT NULL CHECK (type IN ('software_install', 'software_uninstall', 'software_update', 'inventory_full')),
    title         text NOT NULL DEFAULT '',                    -- "Install 7-Zip 24.08" for lists
    body          bytea NOT NULL,                              -- serialized JobEnvelope without issuance fields
    depends_on    uuid REFERENCES jobs(id) ON DELETE SET NULL, -- e.g. user-scope uninstall after a machine install
    not_before    timestamptz NOT NULL,
    expires_at    timestamptz NOT NULL,
    attempt       integer NOT NULL DEFAULT 1,
    status        text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'sent', 'accepted', 'waiting', 'running',
                      'succeeded', 'succeeded_reboot', 'failed', 'expired', 'cancelled', 'rejected')),
    status_reason text NOT NULL DEFAULT '',
    envelope      bytea,                                       -- last signed envelope sent
    created_at    timestamptz NOT NULL DEFAULT now(),
    sent_at       timestamptz,
    acked_at      timestamptz,
    started_at    timestamptz,
    finished_at   timestamptz,
    exit_code     integer,
    detection_passed boolean,
    reboot_required  boolean NOT NULL DEFAULT false,
    cancel_pending   boolean NOT NULL DEFAULT false,           -- cancelled on the server while the agent may still hold it
    result        jsonb
);
CREATE INDEX jobs_device_status ON jobs (device_id, status);
CREATE INDEX jobs_deployment_status ON jobs (deployment_id, status);
CREATE INDEX jobs_depends ON jobs (depends_on) WHERE depends_on IS NOT NULL;

CREATE TABLE job_events (
    id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id  uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    ts      timestamptz NOT NULL DEFAULT now(),
    kind    text NOT NULL,
    message text NOT NULL DEFAULT '',
    data    jsonb
);
CREATE INDEX job_events_job ON job_events (job_id, id);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON
            group_members, catalog_packages, catalog_versions, catalog_installers, package_overrides,
            org_settings, content_blobs, deployments, jobs, job_events
        TO librepatch_app;
        GRANT USAGE ON SEQUENCE job_events_id_seq TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS job_events, jobs, deployments, content_blobs, org_settings, package_overrides,
    catalog_installers, catalog_versions, catalog_packages, group_members CASCADE;
ALTER TABLE groups DROP CONSTRAINT IF EXISTS groups_kind_filter, DROP COLUMN IF EXISTS kind;
