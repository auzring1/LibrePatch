-- +goose Up
-- D164. Agent updates follow the server image by themselves, always. The "roll out new versions automatically" switch is gone;
-- the page now lives under Settings and keeps pause, withdraw, upload and the pilot settings.
ALTER TABLE agent_rollout DROP COLUMN auto_new_release;

-- +goose Down
ALTER TABLE agent_rollout ADD COLUMN auto_new_release boolean NOT NULL DEFAULT false;
