-- +goose Up
-- Catalog overlays (D122): signed files that record what their author knows about packages: silent arguments that really work,
-- extra detection rules, whether a program updates itself, and a "verified" mark. A source is either an uploaded file or a URL
-- that the server refreshes; either way the server accepts a document only if it verifies under the public key the administrator
-- entered, and keeps the verified document here so a restart needs no network.
CREATE TABLE catalog_overlays (
    id            uuid PRIMARY KEY,
    org_id        uuid NOT NULL REFERENCES organizations(id),
    label         text NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
    kind          text NOT NULL CHECK (kind IN ('upload', 'url')),
    url           text NOT NULL DEFAULT '' CHECK (length(url) <= 2000),
    public_key    text NOT NULL CHECK (length(public_key) = 64),
    enabled       boolean NOT NULL DEFAULT true,
    priority      integer NOT NULL DEFAULT 100 CHECK (priority BETWEEN 1 AND 1000),  -- lower wins when two overlays name one package
    doc_name      text NOT NULL DEFAULT '',
    doc_version   bigint NOT NULL DEFAULT 0,
    doc_issued_at text NOT NULL DEFAULT '',
    document      jsonb,
    entries       integer NOT NULL DEFAULT 0,
    fetched_at    timestamptz,
    checked_at    timestamptz,
    status        text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'ok', 'error')),
    last_error    text NOT NULL DEFAULT '' CHECK (length(last_error) <= 500),
    etag          text NOT NULL DEFAULT '' CHECK (length(etag) <= 200),
    created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, label)
);

-- Which overlay (by label) vouches for a package; '' = none. `verified` stays the one flag everything reads (D99): it is true
-- when the package passed the VM test matrix, or an administrator marked it, or an overlay vouches for it.
ALTER TABLE catalog_packages ADD COLUMN verified_by_overlay text NOT NULL DEFAULT '';

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON catalog_overlays TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
ALTER TABLE catalog_packages DROP COLUMN IF EXISTS verified_by_overlay;
DROP TABLE IF EXISTS catalog_overlays;
