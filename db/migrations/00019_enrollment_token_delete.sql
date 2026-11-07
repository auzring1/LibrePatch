-- +goose Up
-- An administrator can delete an enrollment token that can no longer be used (revoked, expired or used up). The
-- devices that enrolled with it stay; they simply no longer point at it. The audit log keeps the token's id and name.
ALTER TABLE devices
    DROP CONSTRAINT devices_enrolled_via_fkey,
    ADD CONSTRAINT devices_enrolled_via_fkey FOREIGN KEY (enrolled_via) REFERENCES enrollment_tokens (id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE devices
    DROP CONSTRAINT devices_enrolled_via_fkey,
    ADD CONSTRAINT devices_enrolled_via_fkey FOREIGN KEY (enrolled_via) REFERENCES enrollment_tokens (id);
