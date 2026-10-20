-- name: UpsertCatalogPackage :one
INSERT INTO catalog_packages (id, org_id, source, identifier, name, publisher, homepage, license, description, self_updating, imported_by)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (org_id, source, identifier) DO UPDATE SET
    name = EXCLUDED.name, publisher = EXCLUDED.publisher, homepage = EXCLUDED.homepage, license = EXCLUDED.license,
    description = EXCLUDED.description, self_updating = EXCLUDED.self_updating, imported_at = now()
RETURNING id;

-- name: UpsertCatalogVersion :one
INSERT INTO catalog_versions (id, package_id, version, version_key, manifest_sha256)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (package_id, version) DO UPDATE SET version_key = EXCLUDED.version_key,
    manifest_sha256 = EXCLUDED.manifest_sha256, imported_at = now()
RETURNING id;

-- name: DeleteVersionInstallers :exec
DELETE FROM catalog_installers WHERE version_id = $1;

-- name: InsertCatalogInstaller :exec
INSERT INTO catalog_installers (id, version_id, architecture, scope, installer_type, nested_type, nested_path, url, sha256, size,
    file_name, signer_subject, product_code, upgrade_code, switches, success_codes, expected_codes, min_os, detection, uses_content_blob, unsupported)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21);

-- name: SetPackageVerified :exec
-- Called by an import: the VM-matrix result decides, and an administrator's mark is kept.
UPDATE catalog_packages SET verified = ($3 OR verified_by_org OR verified_by_overlay <> '') WHERE org_id = $1 AND id = $2;

-- name: SetPackageOrgVerified :exec
-- An administrator marks the package verified (or removes the mark). tests_passed is the VM-matrix result, which keeps the
-- package verified even without the mark.
UPDATE catalog_packages SET
    verified_by_org  = sqlc.arg(by_org)::boolean,
    verified         = (sqlc.arg(by_org)::boolean OR sqlc.arg(tests_passed)::boolean OR verified_by_overlay <> ''),
    verified_by      = CASE WHEN sqlc.arg(by_org)::boolean THEN sqlc.arg(by)::uuid END,
    verified_at      = CASE WHEN sqlc.arg(by_org)::boolean THEN sqlc.arg(at)::timestamptz END,
    verified_version = CASE WHEN sqlc.arg(by_org)::boolean THEN sqlc.arg(version)::text ELSE '' END
WHERE org_id = sqlc.arg(org_id)::uuid AND id = sqlc.arg(id)::uuid;

-- name: ListCatalogPackages :many
SELECT p.*, (SELECT count(*) FROM catalog_versions v WHERE v.package_id = p.id)::int AS version_count
FROM catalog_packages p
WHERE p.org_id = @org_id::uuid
  AND (@q::text = '' OR strpos(lower(p.name), @q::text) > 0 OR strpos(lower(p.identifier), @q::text) > 0 OR strpos(lower(p.publisher), @q::text) > 0)
ORDER BY lower(p.name), p.id
LIMIT @row_limit::int OFFSET @row_offset::int;

-- name: GetCatalogPackage :one
SELECT * FROM catalog_packages WHERE id = $1 AND org_id = $2;

-- name: GetCatalogPackageByIdentifier :one
SELECT * FROM catalog_packages WHERE org_id = $1 AND source = $2 AND identifier = $3;

-- name: ListPackageVersions :many
SELECT * FROM catalog_versions WHERE package_id = $1 ORDER BY version_key DESC NULLS LAST, imported_at DESC;

-- name: GetCatalogVersion :one
SELECT v.* FROM catalog_versions v JOIN catalog_packages p ON p.id = v.package_id WHERE v.id = $1 AND p.org_id = $2;

-- name: ListVersionInstallers :many
SELECT * FROM catalog_installers WHERE version_id = $1 ORDER BY architecture, scope, installer_type, id;

-- name: DeleteCatalogPackage :execrows
DELETE FROM catalog_packages WHERE id = $1 AND org_id = $2;

-- name: GetPackageOverride :one
SELECT * FROM package_overrides WHERE org_id = $1 AND package_id = $2;

-- name: UpsertPackageOverride :exec
INSERT INTO package_overrides (org_id, package_id, silent_args, extra_detection, pin, excluded, user_scope_policy, self_update_policy, processes, updated_by, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
ON CONFLICT (org_id, package_id) DO UPDATE SET silent_args = EXCLUDED.silent_args, extra_detection = EXCLUDED.extra_detection,
    pin = EXCLUDED.pin, excluded = EXCLUDED.excluded, user_scope_policy = EXCLUDED.user_scope_policy,
    self_update_policy = EXCLUDED.self_update_policy, processes = EXCLUDED.processes, updated_by = EXCLUDED.updated_by, updated_at = now();

-- name: GetOrgSettings :one
SELECT * FROM org_settings WHERE org_id = $1;

-- name: UpsertOrgSettings :exec
INSERT INTO org_settings (org_id, user_scope_policy, updated_at) VALUES ($1, $2, now())
ON CONFLICT (org_id) DO UPDATE SET user_scope_policy = EXCLUDED.user_scope_policy, updated_at = now();

-- name: InsertContentBlob :exec
INSERT INTO content_blobs (org_id, sha256, size, file_name, uploaded_by) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (org_id, sha256) DO UPDATE SET file_name = EXCLUDED.file_name;

-- name: GetContentBlob :one
SELECT * FROM content_blobs WHERE org_id = $1 AND sha256 = $2;

-- name: ListAllOrgPackages :many
SELECT * FROM catalog_packages WHERE org_id = $1 ORDER BY lower(name), id LIMIT 2000;
