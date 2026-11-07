-- +goose Up
-- The device page no longer shows lock state and idle time (D163 withdraws D162). 00038 stays so that databases
-- that already ran it keep a matching history; this drops the column again.
ALTER TABLE devices DROP COLUMN IF EXISTS user_sessions;

-- +goose Down
ALTER TABLE devices ADD COLUMN user_sessions jsonb;
