-- +goose Up
-- A dependent job normally waits for its parent to SUCCEED. "finished" lets it run once the parent has
-- ended in any way (used by updates: the install proceeds even if removing an old copy failed).
ALTER TABLE jobs ADD COLUMN depends_when text NOT NULL DEFAULT 'success' CHECK (depends_when IN ('success', 'finished'));

-- +goose Down
ALTER TABLE jobs DROP COLUMN IF EXISTS depends_when;
