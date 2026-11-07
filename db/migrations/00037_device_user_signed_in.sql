-- +goose Up
-- Whether a person has an interactive session on the device (active or disconnected). "loaded" only says their registry file is
-- open, which any program or service running as them keeps true after they have signed out. Existing rows and older agents
-- report false until the device sends its profile list again.
ALTER TABLE device_users ADD COLUMN signed_in boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE device_users DROP COLUMN signed_in;
