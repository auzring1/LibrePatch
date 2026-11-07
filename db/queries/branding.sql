-- name: GetDefaultOrganization :one
-- The organization the public (signed-out) pages describe. An installation has one.
SELECT id, name FROM organizations ORDER BY created_at, id LIMIT 1;

-- name: GetBranding :one
SELECT * FROM branding WHERE org_id = $1;

-- name: UpsertBranding :exec
INSERT INTO branding (org_id, org_name, product_name, accent_color, secondary_color, login_headline, login_message,
                      login_footer, support_email, support_phone, support_url, report_footer, default_theme, allowed_themes, updated_at, updated_by)
VALUES (@org_id, @org_name, @product_name, @accent_color, @secondary_color, @login_headline, @login_message,
        @login_footer, @support_email, @support_phone, @support_url, @report_footer, @default_theme, @allowed_themes, @updated_at, @updated_by)
ON CONFLICT (org_id) DO UPDATE SET
    org_name = EXCLUDED.org_name, product_name = EXCLUDED.product_name, accent_color = EXCLUDED.accent_color,
    secondary_color = EXCLUDED.secondary_color, login_headline = EXCLUDED.login_headline,
    login_message = EXCLUDED.login_message, login_footer = EXCLUDED.login_footer,
    support_email = EXCLUDED.support_email, support_phone = EXCLUDED.support_phone,
    support_url = EXCLUDED.support_url, report_footer = EXCLUDED.report_footer,
    default_theme = EXCLUDED.default_theme, allowed_themes = EXCLUDED.allowed_themes,
    updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by;

-- name: DeleteBranding :exec
DELETE FROM branding WHERE org_id = $1;

-- name: ListBrandingAssets :many
-- Metadata only; the image bytes are read one asset at a time.
SELECT kind, content_type, width, height, sha256, octet_length(content)::bigint AS size, updated_at
FROM branding_assets WHERE org_id = $1 ORDER BY kind;

-- name: GetBrandingAsset :one
SELECT * FROM branding_assets WHERE org_id = $1 AND kind = $2;

-- name: UpsertBrandingAsset :exec
INSERT INTO branding_assets (org_id, kind, content, content_type, width, height, sha256, updated_at, updated_by)
VALUES (@org_id, @kind, @content, @content_type, @width, @height, @sha256, @updated_at, @updated_by)
ON CONFLICT (org_id, kind) DO UPDATE SET
    content = EXCLUDED.content, content_type = EXCLUDED.content_type, width = EXCLUDED.width,
    height = EXCLUDED.height, sha256 = EXCLUDED.sha256, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by;

-- name: DeleteBrandingAsset :execrows
DELETE FROM branding_assets WHERE org_id = $1 AND kind = $2;

-- name: DeleteBrandingAssets :exec
DELETE FROM branding_assets WHERE org_id = $1;

-- name: GetUserPreferences :one
SELECT data FROM user_preferences WHERE user_id = $1;

-- name: UpsertUserPreferences :exec
INSERT INTO user_preferences (user_id, data, updated_at) VALUES (@user_id, @data, @updated_at)
ON CONFLICT (user_id) DO UPDATE SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at;
