-- +goose Up
-- One row per scheduled report that was due (decision D95): it is what makes a schedule send once per due time even if
-- the server restarts or runs twice, and what the console shows as the history of scheduled reports.
CREATE TABLE report_runs (
    org_id      uuid NOT NULL REFERENCES organizations(id),
    schedule_id text NOT NULL,
    due_at      timestamptz NOT NULL,
    started_at  timestamptz NOT NULL DEFAULT now(),
    name        text NOT NULL DEFAULT '',
    report      text NOT NULL DEFAULT '',
    format      text NOT NULL DEFAULT '',
    status      text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'sent', 'failed', 'skipped')),
    error       text NOT NULL DEFAULT '',
    bytes       integer NOT NULL DEFAULT 0,
    recipients  integer NOT NULL DEFAULT 0,
    PRIMARY KEY (org_id, schedule_id, due_at)
);
CREATE INDEX report_runs_recent ON report_runs (org_id, started_at DESC);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON report_runs TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS report_runs;
