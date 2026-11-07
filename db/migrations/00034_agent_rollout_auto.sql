-- +goose Up
-- D149. The server image carries the agent release it was built with; when this is on, a newer bundled release becomes the
-- rollout target by itself (pilot group, soak time and success threshold still apply). Off by default: nothing changes
-- for an installation until an administrator switches it on.
ALTER TABLE agent_rollout ADD COLUMN auto_new_release boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE agent_rollout DROP COLUMN auto_new_release;
