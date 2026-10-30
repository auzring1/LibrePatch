-- name: LockDeviceInventory :one
-- Serializes inventory writes for one device and returns its revisions.
SELECT software_rev, users_rev, org_id FROM devices WHERE id = $1 FOR UPDATE;

-- name: InsertSoftwareTitles :exec
-- Creates the titles that do not exist yet. DO NOTHING (not DO UPDATE) takes no lock on a title that
-- already exists, so thousands of devices ingesting the same common software do not queue behind each
-- other's open transactions. Callers pass the rows in a fixed (sorted) order so that two transactions
-- creating the same new titles cannot deadlock.
INSERT INTO software_titles (id, org_id, normalized_name, normalized_publisher, display_name, display_publisher)
SELECT t.id, @org_id::uuid, t.nn, t.np, t.dn, t.dp
FROM unnest(@ids::uuid[], @normalized_names::text[], @normalized_publishers::text[],
            @display_names::text[], @display_publishers::text[])
     AS t(id, nn, np, dn, dp)
ON CONFLICT (org_id, normalized_name, normalized_publisher) DO NOTHING;

-- name: GetSoftwareTitleIDs :many
-- Run as a separate statement after InsertSoftwareTitles, so it also sees titles another transaction
-- created and committed while ours waited.
SELECT id, normalized_name, normalized_publisher
FROM software_titles
WHERE org_id = @org_id::uuid
  AND (normalized_name, normalized_publisher) IN (
      SELECT t.nn, t.np FROM unnest(@normalized_names::text[], @normalized_publishers::text[]) AS t(nn, np));

-- name: RecordSoftwareChanges :exec
-- History for items that are new or changed version, computed before upserting.
INSERT INTO software_history (device_id, title_id, name, scope, user_sid, change, old_version, new_version, observed_at)
SELECT @device_id::uuid, n.title_id, n.name, n.scope, n.user_sid,
       CASE WHEN o.device_id IS NULL THEN 'added' ELSE 'version' END,
       COALESCE(o.version, ''), n.version, @now::timestamptz
FROM unnest(@sources::text[], @scopes::text[], @user_sids::text[], @item_keys::text[],
            @title_ids::uuid[], @names::text[], @versions::text[])
     AS n(source, scope, user_sid, item_key, title_id, name, version)
LEFT JOIN software_installs o
       ON o.device_id = @device_id::uuid AND o.source = n.source AND o.scope = n.scope
      AND o.user_sid = n.user_sid AND o.item_key = n.item_key
WHERE o.device_id IS NULL OR o.version IS DISTINCT FROM n.version;

-- name: UpsertSoftwareInstalls :exec
INSERT INTO software_installs (device_id, source, scope, user_sid, item_key, title_id, name, version, version_key,
    publisher, install_date, install_location, uninstall_string, quiet_uninstall_string, product_code,
    system_component, first_seen_at, last_seen_at)
SELECT @device_id::uuid, n.source, n.scope, n.user_sid, n.item_key, n.title_id, n.name, n.version, n.version_key,
       n.publisher, n.install_date, n.install_location, n.uninstall_string, n.quiet_uninstall_string, n.product_code,
       n.system_component, @now::timestamptz, @now::timestamptz
FROM unnest(@sources::text[], @scopes::text[], @user_sids::text[], @item_keys::text[], @title_ids::uuid[],
            @names::text[], @versions::text[], @version_keys::bytea[], @publishers::text[], @install_dates::text[],
            @install_locations::text[], @uninstall_strings::text[], @quiet_uninstall_strings::text[],
            @product_codes::text[], @system_components::boolean[])
     AS n(source, scope, user_sid, item_key, title_id, name, version, version_key, publisher, install_date,
          install_location, uninstall_string, quiet_uninstall_string, product_code, system_component)
ON CONFLICT (device_id, source, scope, user_sid, item_key) DO UPDATE SET
    title_id = EXCLUDED.title_id, name = EXCLUDED.name, version = EXCLUDED.version,
    version_key = EXCLUDED.version_key, publisher = EXCLUDED.publisher, install_date = EXCLUDED.install_date,
    install_location = EXCLUDED.install_location, uninstall_string = EXCLUDED.uninstall_string,
    quiet_uninstall_string = EXCLUDED.quiet_uninstall_string, product_code = EXCLUDED.product_code,
    system_component = EXCLUDED.system_component, last_seen_at = EXCLUDED.last_seen_at;

-- name: RemoveSoftwareByKeys :exec
-- Removes the listed items, recording history first.
WITH gone AS (
    DELETE FROM software_installs s
    USING unnest(@sources::text[], @scopes::text[], @user_sids::text[], @item_keys::text[])
          AS k(source, scope, user_sid, item_key)
    WHERE s.device_id = @device_id::uuid AND s.source = k.source AND s.scope = k.scope
      AND s.user_sid = k.user_sid AND s.item_key = k.item_key
    RETURNING s.title_id, s.name, s.scope, s.user_sid, s.version
)
INSERT INTO software_history (device_id, title_id, name, scope, user_sid, change, old_version, new_version, observed_at)
SELECT @device_id::uuid, title_id, name, scope, user_sid, 'removed', version, '', @now::timestamptz FROM gone;

-- name: RemoveSoftwareNotIn :exec
-- Full-snapshot replace: everything not in the snapshot is removed (with history).
WITH gone AS (
    DELETE FROM software_installs s
    WHERE s.device_id = @device_id::uuid
      AND NOT EXISTS (
          SELECT 1
          FROM unnest(@sources::text[], @scopes::text[], @user_sids::text[], @item_keys::text[])
               AS k(source, scope, user_sid, item_key)
          WHERE s.source = k.source AND s.scope = k.scope AND s.user_sid = k.user_sid AND s.item_key = k.item_key)
    RETURNING s.title_id, s.name, s.scope, s.user_sid, s.version
)
INSERT INTO software_history (device_id, title_id, name, scope, user_sid, change, old_version, new_version, observed_at)
SELECT @device_id::uuid, title_id, name, scope, user_sid, 'removed', version, '', @now::timestamptz FROM gone;

-- name: FinishSoftwareSync :exec
UPDATE devices SET software_rev = $2, software_updated_at = $3, inventory_truncated = $4,
       software_count = (SELECT count(*) FROM software_installs WHERE device_id = $1)
WHERE id = $1;

-- name: ListDeviceSoftware :many
SELECT si.source, si.scope, si.user_sid, si.item_key, si.title_id, si.name, si.version, si.publisher,
       si.install_date, si.install_location, si.uninstall_string, si.quiet_uninstall_string, si.product_code,
       si.system_component, si.first_seen_at, si.last_seen_at
FROM software_installs si
WHERE si.device_id = $1 AND (@include_system::boolean OR NOT si.system_component)
ORDER BY lower(si.name), si.scope, si.user_sid, si.source, si.item_key;

-- name: ListDeviceSoftwareHistory :many
SELECT id, title_id, name, scope, user_sid, change, old_version, new_version, observed_at
FROM software_history WHERE device_id = @device_id::uuid AND (@before_id::bigint = 0 OR id < @before_id::bigint)
ORDER BY id DESC LIMIT @row_limit::int;

-- name: ReplaceUsersDelete :exec
DELETE FROM device_users WHERE device_id = $1 AND NOT (sid = ANY(@sids::text[]));

-- name: UpsertDeviceUsers :exec
INSERT INTO device_users (device_id, sid, username, domain, profile_path, last_logon_at, loaded, is_admin)
SELECT @device_id::uuid, n.sid, n.username, n.domain, n.profile_path,
       CASE WHEN n.last_logon > 0 THEN to_timestamp(n.last_logon) END, n.loaded, n.is_admin
FROM unnest(@sids::text[], @usernames::text[], @domains::text[], @profile_paths::text[], @last_logons::bigint[],
            @loaded::boolean[], @is_admins::boolean[])
     AS n(sid, username, domain, profile_path, last_logon, loaded, is_admin)
ON CONFLICT (device_id, sid) DO UPDATE SET
    username = EXCLUDED.username, domain = EXCLUDED.domain, profile_path = EXCLUDED.profile_path,
    last_logon_at = EXCLUDED.last_logon_at, loaded = EXCLUDED.loaded, is_admin = EXCLUDED.is_admin;

-- name: SetUsersRev :exec
UPDATE devices SET users_rev = $2 WHERE id = $1;

-- name: GetDeviceUser :one
SELECT * FROM device_users WHERE device_id = $1 AND sid = $2;

-- name: DeleteDeviceUser :exec
DELETE FROM device_users WHERE device_id = $1 AND sid = $2;

-- name: ListDeviceUsers :many
SELECT * FROM device_users WHERE device_id = $1 ORDER BY loaded DESC, lower(username), sid;

-- name: SearchSoftwareTitles :many
-- Fleet-wide software list: one row per product with how many (active) devices have it.
SELECT st.id, st.display_name, st.display_publisher,
       count(DISTINCT si.device_id)::int AS device_count,
       count(DISTINCT si.version)::int AS version_count,
       count(*) OVER ()::bigint AS total
FROM software_titles st
JOIN software_installs si ON si.title_id = st.id
JOIN devices d ON d.id = si.device_id AND d.status = 'active'
WHERE st.org_id = @org_id::uuid
  AND (@include_system::boolean OR NOT si.system_component)
  AND (@q::text = '' OR strpos(st.normalized_name, @q::text) > 0 OR strpos(st.normalized_publisher, @q::text) > 0)
GROUP BY st.id
ORDER BY device_count DESC, lower(st.display_name), st.id
LIMIT @row_limit::int OFFSET @row_offset::int;

-- name: SearchSoftwareTitlesNoSystem :many
-- SearchSoftwareTitles without system components (the page's default view). The condition is written out instead of
-- passed as a parameter so the planner can use software_installs_title_device, a partial index on that condition.
SELECT st.id, st.display_name, st.display_publisher,
       count(DISTINCT si.device_id)::int AS device_count,
       count(DISTINCT si.version)::int AS version_count,
       count(*) OVER ()::bigint AS total
FROM software_titles st
JOIN software_installs si ON si.title_id = st.id
JOIN devices d ON d.id = si.device_id AND d.status = 'active'
WHERE st.org_id = @org_id::uuid
  AND NOT si.system_component
  AND (@q::text = '' OR strpos(st.normalized_name, @q::text) > 0 OR strpos(st.normalized_publisher, @q::text) > 0)
GROUP BY st.id
ORDER BY device_count DESC, lower(st.display_name), st.id
LIMIT @row_limit::int OFFSET @row_offset::int;

-- name: GetSoftwareTitle :one
SELECT * FROM software_titles WHERE id = @id::uuid AND org_id = @org_id::uuid;

-- name: ListTitleVersions :many
-- Versions of one product across the fleet, newest first (by comparable version key).
SELECT si.version, count(DISTINCT si.device_id)::int AS device_count
FROM software_installs si
JOIN devices d ON d.id = si.device_id AND d.status = 'active'
WHERE si.title_id = @title_id::uuid AND d.org_id = @org_id::uuid
GROUP BY si.version, si.version_key
ORDER BY si.version_key DESC NULLS LAST, si.version;

-- name: ListTitleInstalls :many
SELECT d.id AS device_id, d.hostname, d.online, si.version, si.scope, si.user_sid, si.source,
       si.install_date, si.install_location, si.last_seen_at,
       count(*) OVER ()::bigint AS total
FROM software_installs si
JOIN devices d ON d.id = si.device_id AND d.status = 'active'
WHERE si.title_id = @title_id::uuid AND d.org_id = @org_id::uuid
  AND (@version::text = '' OR si.version = @version::text)
  AND (sqlc.narg('older_than')::bytea IS NULL OR si.version_key < sqlc.narg('older_than')::bytea)
ORDER BY lower(d.hostname), d.id, si.user_sid, si.source, si.item_key
LIMIT @row_limit::int OFFSET @row_offset::int;

-- name: GetDeviceInstall :one
SELECT si.name, si.version, si.system_component, si.product_code
FROM software_installs si
WHERE si.device_id = $1 AND si.source = $2 AND si.scope = $3 AND si.user_sid = $4 AND si.item_key = $5;

-- name: ListDeviceInstallRows :many
-- Everything a device reports that could be matched to a catalog package (for "missing updates").
SELECT si.source, si.scope, si.user_sid, si.item_key, si.name, si.version, si.version_key, si.publisher, si.product_code, st.normalized_name
FROM software_installs si JOIN software_titles st ON st.id = si.title_id
WHERE si.device_id = $1 AND NOT si.system_component
ORDER BY lower(si.name), si.scope, si.user_sid, si.item_key;

-- name: ListFleetInstallGroups :many
-- The distinct programs installed on active devices, told apart only as far as matching them to a catalog or winget
-- package can tell them apart (not by device). One row per program instead of one per device and program: a fleet of
-- 5,000 PCs reports about 600,000 install rows but a few thousand distinct programs. Grouping by title id first keeps
-- the planner on a hash aggregate (grouping by the long text columns after the join made it sort 40 MB on disk).
SELECT g.title_id, st.normalized_name, g.source, g.item_key, g.name, g.version, g.version_key, g.publisher, g.product_code
FROM (
  SELECT si.title_id, si.source, si.item_key, si.name, si.version, si.version_key, si.publisher, si.product_code
  FROM software_installs si
  WHERE NOT si.system_component AND si.source NOT IN ('appx', 'portable')
    AND EXISTS (SELECT 1 FROM devices d WHERE d.id = si.device_id AND d.org_id = @org_id::uuid AND d.status = 'active')
  GROUP BY si.title_id, si.source, si.item_key, si.name, si.version, si.version_key, si.publisher, si.product_code
) g
JOIN software_titles st ON st.id = g.title_id;

-- name: ListFleetInstallRowsForTitles :many
-- ListFleetInstallRows restricted to some products (the ones with an update), in the same order.
SELECT si.device_id, d.hostname, si.source, si.scope, si.user_sid, si.item_key, si.name, si.version, si.version_key,
       si.publisher, si.product_code, st.normalized_name
FROM software_installs si
JOIN software_titles st ON st.id = si.title_id
JOIN devices d ON d.id = si.device_id
WHERE si.title_id = ANY(@title_ids::uuid[])
  AND d.org_id = @org_id::uuid AND d.status = 'active' AND NOT si.system_component AND si.source NOT IN ('appx', 'portable')
ORDER BY lower(d.hostname), lower(si.name), si.scope, si.user_sid, si.item_key;

-- name: ListFleetInstallRows :many
-- Installed programs on every active device that could be matched to a catalog or winget package (for the fleet-wide
-- "Software updates" page). Store apps and portable programs are left out: neither can be updated by an installer.
SELECT si.device_id, d.hostname, si.source, si.scope, si.user_sid, si.item_key, si.name, si.version, si.version_key,
       si.publisher, si.product_code, st.normalized_name
FROM software_installs si
JOIN software_titles st ON st.id = si.title_id
JOIN devices d ON d.id = si.device_id
WHERE d.org_id = $1 AND d.status = 'active' AND NOT si.system_component AND si.source NOT IN ('appx', 'portable')
ORDER BY lower(d.hostname), lower(si.name), si.scope, si.user_sid, si.item_key;
