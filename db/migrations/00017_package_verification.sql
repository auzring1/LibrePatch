-- +goose Up
-- An administrator can mark a catalog package as verified after testing it themselves (decision D99). `verified` stays the
-- single flag everything reads (the confirmation before deploying, the labels, software policies); it is true when the
-- package passed the VM test matrix OR an administrator marked it. These columns record the administrator's mark, so an
-- import of a newer version does not wipe it, and say who made it, when, and for which version.
ALTER TABLE catalog_packages
    ADD COLUMN verified_by_org  boolean     NOT NULL DEFAULT false,
    ADD COLUMN verified_by      uuid        REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN verified_at      timestamptz,
    ADD COLUMN verified_version text        NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE catalog_packages
    DROP COLUMN IF EXISTS verified_version,
    DROP COLUMN IF EXISTS verified_at,
    DROP COLUMN IF EXISTS verified_by,
    DROP COLUMN IF EXISTS verified_by_org;
