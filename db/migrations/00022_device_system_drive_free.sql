-- +goose Up
-- The free space of the system drive, as the agent's last heartbeat reported it (NULL until it has). The hardware
-- snapshot also holds disk sizes, but it is only re-sent when something other than free space changes, so it goes
-- stale; the low-disk notification needs a current value.
ALTER TABLE devices ADD COLUMN system_drive_free_bytes bigint;

-- +goose Down
ALTER TABLE devices DROP COLUMN IF EXISTS system_drive_free_bytes;
