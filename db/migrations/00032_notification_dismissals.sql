-- +goose Up
-- D146. A person can dismiss an item of their notification bell. The bell is computed from the current state (failed jobs of
-- the last 24 hours, open holds), so what is stored is only "this person has seen this one": the id of the item. It is per
-- person (one person's dismissal never hides an item from a colleague) and it goes away with the person; the rows of items
-- that no longer exist are removed the next time the bell is read.
CREATE TABLE notification_dismissals (
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_id      text NOT NULL CHECK (length(item_id) BETWEEN 1 AND 100),
    dismissed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, item_id)
);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON notification_dismissals TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS notification_dismissals;
