-- name: ListGroups :many
SELECT * FROM groups WHERE org_id = $1 ORDER BY lower(name), id LIMIT 500;

-- name: GetGroup :one
SELECT * FROM groups WHERE id = $1 AND org_id = $2;

-- name: CreateGroup :exec
INSERT INTO groups (id, org_id, name, description, kind, filter, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7);

-- name: UpdateGroup :execrows
UPDATE groups SET name = $3, description = $4, filter = $5, updated_at = $6
WHERE id = $1 AND org_id = $2;

-- name: DeleteGroup :execrows
DELETE FROM groups WHERE id = $1 AND org_id = $2;

-- name: ListGroupMembers :many
-- Members of a static group (active or not; the console shows status).
SELECT d.id, d.hostname, d.status, d.online, d.os_caption, d.chassis, d.manufacturer, d.model, d.last_seen_at, d.software_count
FROM group_members m JOIN devices d ON d.id = m.device_id
WHERE m.group_id = $1 AND d.org_id = $2
ORDER BY lower(d.hostname), d.id
LIMIT $3 OFFSET $4;

-- name: CountGroupMembers :one
SELECT count(*) FROM group_members m JOIN devices d ON d.id = m.device_id WHERE m.group_id = $1 AND d.org_id = $2;

-- name: AddGroupMembers :exec
INSERT INTO group_members (group_id, device_id, added_by)
SELECT @group_id::uuid, d.id, @added_by::uuid FROM devices d
WHERE d.org_id = @org_id::uuid AND d.id = ANY(@device_ids::uuid[])
ON CONFLICT DO NOTHING;

-- name: RemoveGroupMembers :exec
DELETE FROM group_members m USING groups g
WHERE m.group_id = g.id AND g.id = @group_id::uuid AND g.org_id = @org_id::uuid AND m.device_id = ANY(@device_ids::uuid[]);
