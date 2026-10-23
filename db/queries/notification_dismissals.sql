-- name: ListNotificationDismissals :many
SELECT item_id FROM notification_dismissals WHERE user_id = $1;

-- name: DismissNotifications :exec
INSERT INTO notification_dismissals (user_id, item_id)
SELECT $1, unnest($2::text[])
ON CONFLICT (user_id, item_id) DO NOTHING;

-- name: ForgetNotificationDismissals :exec
DELETE FROM notification_dismissals WHERE user_id = $1 AND item_id = ANY($2::text[]);
