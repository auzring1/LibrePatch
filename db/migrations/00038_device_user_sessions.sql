-- +goose Up
-- The Windows sessions people are signed in to, with lock state and idle time, from the agent's heartbeat (D162).
-- NULL means the agent does not report them (older agents); the console then says "not reported".
-- Shape: {"reported_at": timestamp, "sessions": [{"user", "station", "disconnected", "lock", "signed_in_at", "idle_since"}]}
ALTER TABLE devices ADD COLUMN user_sessions jsonb;

-- +goose Down
ALTER TABLE devices DROP COLUMN user_sessions;
