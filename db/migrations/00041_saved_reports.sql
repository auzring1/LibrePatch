-- +goose Up
-- D166. Custom reports: a saved report is a name and a "spec" (which data, which columns, which filters, which scope).
-- It holds no data of its own; every run reads the live inventory, so a saved report never goes stale.
CREATE TABLE saved_reports (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations(id),
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    description text NOT NULL DEFAULT '' CHECK (length(description) <= 500),
    spec        jsonb NOT NULL,
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX saved_reports_name ON saved_reports (org_id, lower(name));

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON saved_reports TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS saved_reports;
