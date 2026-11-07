-- +goose Up
-- Sharing downloaded installers between computers on one network (D126).

-- The port an agent says it shares downloads on (0 = not sharing); reported with every heartbeat.
ALTER TABLE devices ADD COLUMN peer_port integer NOT NULL DEFAULT 0 CHECK (peer_port BETWEEN 0 AND 65535);

-- Which devices have installed (and so downloaded) which installer, to offer them as peers. A row means "this device
-- finished an install or update from this file"; the file may since have been removed from its cache, which costs a 404.
CREATE TABLE peer_content (
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sha256    bytea NOT NULL CHECK (octet_length(sha256) = 32),
    seen_at   timestamptz NOT NULL,
    PRIMARY KEY (device_id, sha256)
);
CREATE INDEX peer_content_sha ON peer_content (sha256, seen_at DESC);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON peer_content TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS peer_content;
ALTER TABLE devices DROP COLUMN IF EXISTS peer_port;
