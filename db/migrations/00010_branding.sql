-- +goose Up
-- Per-deployment branding (decision D92): organization name, product name override, colors, login page
-- texts, report footer and five images. Everything is optional; an empty value means "use the default"
-- (product "LibrePatch", no organization name, the default accent color, no logo). Images are stored
-- here, already re-encoded to PNG by the server, so there is no file path to attack.

CREATE TABLE branding (
    org_id          uuid PRIMARY KEY REFERENCES organizations(id),
    org_name        text NOT NULL DEFAULT '' CHECK (char_length(org_name) <= 120),
    product_name    text NOT NULL DEFAULT '' CHECK (char_length(product_name) <= 60),
    accent_color    text NOT NULL DEFAULT '' CHECK (accent_color = '' OR accent_color ~ '^#[0-9a-f]{6}$'),
    secondary_color text NOT NULL DEFAULT '' CHECK (secondary_color = '' OR secondary_color ~ '^#[0-9a-f]{6}$'),
    login_headline  text NOT NULL DEFAULT '' CHECK (char_length(login_headline) <= 120),
    login_message   text NOT NULL DEFAULT '' CHECK (char_length(login_message) <= 1000),
    login_footer    text NOT NULL DEFAULT '' CHECK (char_length(login_footer) <= 1000),
    support_email   text NOT NULL DEFAULT '' CHECK (char_length(support_email) <= 254),
    support_phone   text NOT NULL DEFAULT '' CHECK (char_length(support_phone) <= 40),
    support_url     text NOT NULL DEFAULT '' CHECK (char_length(support_url) <= 300),
    report_footer   text NOT NULL DEFAULT '' CHECK (char_length(report_footer) <= 500),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      uuid REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE branding_assets (
    org_id       uuid NOT NULL REFERENCES organizations(id),
    kind         text NOT NULL CHECK (kind IN ('logo_light', 'logo_dark', 'icon', 'favicon', 'report_logo')),
    content      bytea NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 524288),
    content_type text NOT NULL CHECK (content_type = 'image/png'),
    width        integer NOT NULL CHECK (width BETWEEN 1 AND 4096),
    height       integer NOT NULL CHECK (height BETWEEN 1 AND 4096),
    sha256       bytea NOT NULL CHECK (octet_length(sha256) = 32),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    updated_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (org_id, kind)
);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON branding, branding_assets TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS branding_assets, branding CASCADE;
