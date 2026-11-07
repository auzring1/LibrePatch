-- +goose Up
-- Values of the custom device fields an administrator defines under Settings > Device defaults (decision D95). The
-- definitions live in the settings; a value whose field was removed is simply no longer shown.
CREATE TABLE device_custom_values (
    device_id  uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    field_key  text NOT NULL CHECK (field_key ~ '^[a-z][a-z0-9_]{0,29}$'),
    value      text NOT NULL CHECK (length(value) BETWEEN 1 AND 500),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (device_id, field_key)
);
CREATE INDEX device_custom_values_lookup ON device_custom_values (field_key, value);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON device_custom_values TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS device_custom_values;
