-- +goose Up
-- The master key of a stack that generated it automatically (decision D109). The one-shot maintenance service inserts
-- the row when it creates the key; the console then makes the first administrator save the key before it lets them
-- continue, and records who did. A stack whose key was supplied by hand has no row and never shows the screen.
CREATE TABLE master_key_ack (
    id               integer PRIMARY KEY CHECK (id = 1),
    key_id           text NOT NULL,
    generated_at     timestamptz NOT NULL DEFAULT now(),
    acknowledged_at  timestamptz,
    acknowledged_by  uuid REFERENCES users(id) ON DELETE SET NULL
);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, UPDATE ON master_key_ack TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS master_key_ack;
