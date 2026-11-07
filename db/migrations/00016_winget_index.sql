-- +goose Up
-- The winget community source index (decision D98): the file the winget client uses to recognise installed programs and
-- to know the newest version of every package. One row, replaced by each refresh. It is public data that can be
-- downloaded again at any time; it is kept so the server can match installed software right after a restart, with
-- no network access.
CREATE TABLE winget_index (
    id              smallint PRIMARY KEY CHECK (id = 1),
    data            bytea,                          -- the downloaded package file (source2.msix)
    fetched_at      timestamptz,
    source_modified timestamptz,
    etag            text NOT NULL DEFAULT '',
    last_modified   text NOT NULL DEFAULT '',
    package_count   integer NOT NULL DEFAULT 0,
    checked_at      timestamptz,                    -- last attempt, successful or not
    last_error      text NOT NULL DEFAULT ''
);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON winget_index TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS winget_index;
