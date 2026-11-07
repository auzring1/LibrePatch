-- +goose Up
-- LibrePatch is open source (decision D100): there are no license keys and no device cap. The tables that held
-- installed licenses and the clock high-water mark are no longer used.
DROP TABLE IF EXISTS license_clock, licenses CASCADE;

-- +goose Down
CREATE TABLE licenses (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations(id),
    license_id   text NOT NULL CHECK (length(license_id) BETWEEN 1 AND 64),
    key_id       text NOT NULL,
    blob         text NOT NULL CHECK (length(blob) <= 16384),
    installed_by uuid REFERENCES users(id) ON DELETE SET NULL,
    installed_at timestamptz NOT NULL
);
CREATE INDEX licenses_org_installed ON licenses (org_id, installed_at DESC, id DESC);

CREATE TABLE license_clock (
    singleton  boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    high_water timestamptz NOT NULL
);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT ON licenses TO librepatch_app;
        GRANT SELECT, INSERT, UPDATE ON license_clock TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd
