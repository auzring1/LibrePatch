-- name: GetMasterKeyAck :one
SELECT key_id, generated_at, acknowledged_at FROM master_key_ack WHERE id = 1;

-- name: UpsertMasterKeyAck :exec
-- Run by the maintenance service (schema owner) when it creates a key. A row that was already acknowledged is kept.
INSERT INTO master_key_ack (id, key_id) VALUES (1, $1)
ON CONFLICT (id) DO UPDATE SET key_id = EXCLUDED.key_id, generated_at = now()
WHERE master_key_ack.acknowledged_at IS NULL;

-- name: AcknowledgeMasterKey :execrows
UPDATE master_key_ack SET acknowledged_at = $1, acknowledged_by = $2 WHERE id = 1 AND acknowledged_at IS NULL;

-- name: DatabaseHoldsSealedData :one
-- True when the database already holds anything the master key seals: a missing key must then never be replaced.
SELECT (EXISTS (SELECT 1 FROM pki_material) OR EXISTS (SELECT 1 FROM setup_state) OR EXISTS (SELECT 1 FROM mfa_totp))::boolean;
