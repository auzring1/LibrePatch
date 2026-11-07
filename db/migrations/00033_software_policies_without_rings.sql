-- +goose Up
-- Software policies no longer roll out through update rings (D148): rings are for Windows updates only. A policy that was
-- set to use them would otherwise keep staging with no way to see or switch that off in the console.
UPDATE software_policies SET use_rings = false WHERE use_rings;
UPDATE software_auto_policies SET use_rings = false WHERE use_rings;

-- +goose Down
-- The old setting is not restored: which policies used rings is not kept.
SELECT 1;
