-- +goose Up
-- The script library and runs of scripts on devices (D127).

ALTER TABLE jobs DROP CONSTRAINT jobs_type_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_type_check CHECK (type IN
    ('software_install', 'software_uninstall', 'software_update', 'inventory_full', 'wu_scan', 'wu_install', 'wu_hide', 'reboot', 'agent_update',
     'wake', 'inspect', 'run_script'));

CREATE TABLE scripts (
    id              uuid PRIMARY KEY,
    org_id          uuid NOT NULL REFERENCES organizations(id),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    interpreter     text NOT NULL DEFAULT 'powershell' CHECK (interpreter IN ('powershell')),
    current_version integer NOT NULL DEFAULT 1,
    created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

-- Every save is a new version; a version never changes, so "what ran" can always be shown.
CREATE TABLE script_versions (
    script_id  uuid NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    version    integer NOT NULL,
    content    text NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 65536),
    sha256     bytea NOT NULL CHECK (octet_length(sha256) = 32),
    note       text NOT NULL DEFAULT '' CHECK (length(note) <= 200),
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (script_id, version)
);

-- A request to run one version of a script on devices. The content is copied in, so deleting the script does not change what
-- the history says ran, and an approver approves exactly what will be sent.
CREATE TABLE script_runs (
    id               uuid PRIMARY KEY,
    org_id           uuid NOT NULL REFERENCES organizations(id),
    script_id        uuid REFERENCES scripts(id) ON DELETE SET NULL,
    script_name      text NOT NULL,
    version          integer NOT NULL,
    interpreter      text NOT NULL,
    content          text NOT NULL,
    sha256           bytea NOT NULL CHECK (octet_length(sha256) = 32),
    timeout_s        integer NOT NULL CHECK (timeout_s BETWEEN 10 AND 3600),
    reason           text NOT NULL CHECK (length(reason) BETWEEN 1 AND 200),
    target_group_ids  uuid[] NOT NULL DEFAULT '{}',
    target_device_ids uuid[] NOT NULL DEFAULT '{}',
    status           text NOT NULL CHECK (status IN ('pending_approval', 'running', 'rejected', 'cancelled', 'expired')),
    requested_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    requested_at     timestamptz NOT NULL DEFAULT now(),
    decided_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at       timestamptz,
    decision_note    text NOT NULL DEFAULT '' CHECK (length(decision_note) <= 200),
    devices          integer NOT NULL DEFAULT 0
);
CREATE INDEX script_runs_org ON script_runs (org_id, requested_at DESC);

ALTER TABLE jobs ADD COLUMN script_run_id uuid REFERENCES script_runs(id) ON DELETE SET NULL;
CREATE INDEX jobs_script_run ON jobs (script_run_id) WHERE script_run_id IS NOT NULL;

-- What a script printed. It is not part of the job result that job pages show to everyone who may read deployments, because
-- scripts print whatever they like; only people who may read scripts see it, and it is deleted after 30 days.
CREATE TABLE script_outputs (
    job_id     uuid PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    run_id     uuid NOT NULL REFERENCES script_runs(id) ON DELETE CASCADE,
    exit_code  integer NOT NULL,
    output     text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX script_outputs_created ON script_outputs (created_at);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON scripts, script_versions, script_runs, script_outputs TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS script_outputs;
ALTER TABLE jobs DROP COLUMN IF EXISTS script_run_id;
DROP TABLE IF EXISTS script_runs, script_versions, scripts;
ALTER TABLE jobs DROP CONSTRAINT jobs_type_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_type_check CHECK (type IN
    ('software_install', 'software_uninstall', 'software_update', 'inventory_full', 'wu_scan', 'wu_install', 'wu_hide', 'reboot', 'agent_update', 'wake', 'inspect'));
