-- +goose Up
-- Console appearance (decision D93): the organization's default theme and which themes users may pick
-- (empty = all offered), and each user's own preferences (theme, table density, saved table views), which follow the
-- account to any device. Theme ids are checked for shape only, so adding a theme to the console needs no server change.

ALTER TABLE branding
    ADD COLUMN default_theme  text   NOT NULL DEFAULT '' CHECK (default_theme = '' OR default_theme ~ '^[a-z][a-z0-9-]{0,31}$'),
    ADD COLUMN allowed_themes text[] NOT NULL DEFAULT '{}' CHECK (cardinality(allowed_themes) <= 16);

CREATE TABLE user_preferences (
    user_id    uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    data       jsonb NOT NULL DEFAULT '{}' CHECK (pg_column_size(data) <= 65536),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON user_preferences TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS user_preferences;
ALTER TABLE branding DROP COLUMN IF EXISTS allowed_themes, DROP COLUMN IF EXISTS default_theme;
