-- name: InsertCatalogOverlay :exec
INSERT INTO catalog_overlays (id, org_id, label, kind, url, public_key, enabled, priority, doc_name, doc_version, doc_issued_at, document, entries,
    fetched_at, checked_at, status, last_error, etag, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14, 'ok', '', $15, $16);

-- name: GetCatalogOverlay :one
SELECT * FROM catalog_overlays WHERE id = $1 AND org_id = $2;

-- name: ListCatalogOverlays :many
SELECT * FROM catalog_overlays WHERE org_id = $1 ORDER BY priority, created_at, id;

-- name: ListEnabledCatalogOverlays :many
SELECT * FROM catalog_overlays WHERE enabled AND document IS NOT NULL ORDER BY org_id, priority, created_at, id;

-- name: UpdateCatalogOverlaySettings :execrows
UPDATE catalog_overlays SET label = $3, enabled = $4, priority = $5, url = $6, updated_at = now() WHERE id = $1 AND org_id = $2;

-- name: SaveCatalogOverlayDocument :execrows
UPDATE catalog_overlays SET doc_name = $3, doc_version = $4, doc_issued_at = $5, document = $6, entries = $7, fetched_at = $8, checked_at = $8,
    status = 'ok', last_error = '', etag = $9, updated_at = now()
WHERE id = $1 AND org_id = $2;

-- name: SetCatalogOverlayChecked :exec
-- A refresh that found nothing new (not modified, or the same version) or failed. Keeps the document it has.
UPDATE catalog_overlays SET checked_at = $2, status = $3, last_error = $4, updated_at = now() WHERE id = $1;

-- name: DeleteCatalogOverlay :execrows
DELETE FROM catalog_overlays WHERE id = $1 AND org_id = $2;

-- name: ListDueOverlayRefreshes :many
SELECT id, org_id FROM catalog_overlays WHERE kind = 'url' AND enabled AND (checked_at IS NULL OR checked_at < $1) ORDER BY checked_at NULLS FIRST LIMIT 20;

-- name: ListPackageOverlayState :many
SELECT id, identifier, self_updating, verified, verified_by_org, verified_by_overlay FROM catalog_packages WHERE org_id = $1 AND source = 'winget';

-- name: SetPackageOverlayState :exec
-- Applies what the overlays say: self_updating where an overlay says it, and which overlay vouches (''= none). tests_passed is the
-- VM-matrix result.
UPDATE catalog_packages SET
    self_updating       = sqlc.arg(self_updating)::boolean,
    verified_by_overlay = sqlc.arg(overlay)::text,
    verified            = (sqlc.arg(tests_passed)::boolean OR verified_by_org OR sqlc.arg(overlay)::text <> '')
WHERE org_id = sqlc.arg(org_id)::uuid AND id = sqlc.arg(id)::uuid;
