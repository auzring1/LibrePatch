-- +goose Up
-- Phase 6: offline-verifiable license keys (decision D85). Every installed license is kept (insert-only
-- history); the newest row is the one in force. The signed text is authoritative and is verified again
-- every time it is used, so a row edited in the database cannot change the cap.

CREATE TABLE licenses (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations(id),
    license_id   text NOT NULL CHECK (length(license_id) BETWEEN 1 AND 64),
    key_id       text NOT NULL,                 -- which vendor key verified it at install time
    blob         text NOT NULL CHECK (length(blob) <= 16384),   -- RNL1.<document>.<signature>
    installed_by uuid REFERENCES users(id) ON DELETE SET NULL,
    installed_at timestamptz NOT NULL
);
CREATE INDEX licenses_org_installed ON licenses (org_id, installed_at DESC, id DESC);

-- The highest server time ever observed, so turning the clock back does not revive an expired
-- subscription. One row for the whole installation.
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

-- +goose Down
DROP TABLE IF EXISTS license_clock, licenses CASCADE;
