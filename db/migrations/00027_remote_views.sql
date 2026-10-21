-- +goose Up
-- Wake-on-LAN and read-only views of a device (D125): two new job types, and a short-lived place for what a view returned.
ALTER TABLE jobs DROP CONSTRAINT jobs_type_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_type_check CHECK (type IN
    ('software_install', 'software_uninstall', 'software_update', 'inventory_full', 'wu_scan', 'wu_install', 'wu_hide', 'reboot', 'agent_update',
     'wake', 'inspect'));

-- What a view (running programs, services, event log) returned. It is not part of the job result, so the job pages that
-- show results to everyone who may read deployments never carry it; only people who may inspect the device read it, and
-- a row is deleted an hour after it was written.
CREATE TABLE device_views (
    job_id     uuid PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
    org_id     uuid NOT NULL REFERENCES organizations(id),
    device_id  uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind       text NOT NULL CHECK (kind IN ('processes', 'services', 'events')),
    data       jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX device_views_created ON device_views (created_at);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON device_views TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS device_views;
ALTER TABLE jobs DROP CONSTRAINT jobs_type_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_type_check CHECK (type IN
    ('software_install', 'software_uninstall', 'software_update', 'inventory_full', 'wu_scan', 'wu_install', 'wu_hide', 'reboot', 'agent_update'));
