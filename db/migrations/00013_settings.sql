-- +goose Up
-- Organization settings (decision D95): one JSON document per section, with a revision for optimistic concurrency and
-- the sealed secrets (SMTP password, webhook signing secrets) kept apart from the values so an export can never
-- carry them. The outbox holds notifications until they are sent (retries, quiet hours, de-duplication).

CREATE TABLE settings_sections (
    org_id         uuid   NOT NULL REFERENCES organizations(id),
    section        text   NOT NULL CHECK (section ~ '^[a-z][a-z_]{0,29}$'),
    revision       bigint NOT NULL DEFAULT 1,
    schema_version integer NOT NULL,
    data           jsonb  NOT NULL CHECK (pg_column_size(data) <= 262144),
    secrets        jsonb  NOT NULL DEFAULT '{}' CHECK (pg_column_size(secrets) <= 65536),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    updated_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (org_id, section)
);

CREATE TABLE notification_outbox (
    id          bigserial PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations(id),
    channel     text NOT NULL CHECK (channel IN ('email', 'webhook')),
    event       text NOT NULL,
    target      text NOT NULL,                  -- an e-mail address or a webhook id
    dedupe_key  text NOT NULL DEFAULT '',
    payload     jsonb NOT NULL,
    status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    attempts    integer NOT NULL DEFAULT 0,
    not_before  timestamptz NOT NULL DEFAULT now(),
    last_error  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    sent_at     timestamptz
);
CREATE INDEX notification_outbox_due ON notification_outbox (not_before) WHERE status = 'pending';
CREATE INDEX notification_outbox_created ON notification_outbox (org_id, created_at DESC);
CREATE UNIQUE INDEX notification_outbox_dedupe ON notification_outbox (org_id, channel, target, event, dedupe_key) WHERE dedupe_key <> '';

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON settings_sections, notification_outbox TO librepatch_app;
        GRANT USAGE, SELECT ON SEQUENCE notification_outbox_id_seq TO librepatch_app;
        GRANT SELECT ON goose_db_version TO librepatch_app; -- the About page shows the schema version
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS notification_outbox;
DROP TABLE IF EXISTS settings_sections;
