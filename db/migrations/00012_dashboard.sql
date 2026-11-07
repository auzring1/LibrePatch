-- +goose Up
-- The dashboard's patch-compliance chart (decision D94): one row per site and day, rewritten through the day by an
-- hourly snapshot so the last row of a day is its closing state. Kept per site so a site-limited administrator's
-- chart adds up only the sites they may see.
CREATE TABLE compliance_snapshots (
    org_id        uuid NOT NULL REFERENCES organizations(id),
    site_id       uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    taken_on      date NOT NULL,
    compliant     integer NOT NULL CHECK (compliant >= 0),
    non_compliant integer NOT NULL CHECK (non_compliant >= 0),
    unknown       integer NOT NULL CHECK (unknown >= 0),
    taken_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, site_id, taken_on)
);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON compliance_snapshots TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS compliance_snapshots;
