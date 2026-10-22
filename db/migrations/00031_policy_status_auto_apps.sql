-- +goose Up
-- D132. Every software policy records what its last check found (so the console can say "Up to date", "Waiting for your
-- approval of 24.08" and link to the last deployment), and a new kind of policy, "all apps", keeps every app that has an
-- update current. An all-apps policy is a parent row here; each app it handles is an ordinary one-package policy (a
-- child, auto_policy_id set) that the server creates when an update appears, so rings, approval, holds and attempts work
-- exactly as they do for a policy made by hand.

ALTER TABLE software_policies
    ADD COLUMN last_check_at      timestamptz,
    ADD COLUMN last_state         text NOT NULL DEFAULT '',
    ADD COLUMN last_detail        text NOT NULL DEFAULT '',
    ADD COLUMN last_run_at        timestamptz,   -- when the policy last created a deployment
    ADD COLUMN last_deployment_id uuid,          -- no foreign key: old deployments may be pruned
    ADD COLUMN auto_policy_id     uuid;

CREATE TABLE software_auto_policies (
    id               uuid PRIMARY KEY,
    org_id           uuid NOT NULL REFERENCES organizations(id),
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    group_ids        uuid[] NOT NULL CHECK (cardinality(group_ids) BETWEEN 1 AND 50),
    delay_days       integer NOT NULL DEFAULT 0 CHECK (delay_days BETWEEN 0 AND 365),
    maint_window     jsonb,
    enabled          boolean NOT NULL DEFAULT true,
    use_rings        boolean NOT NULL DEFAULT false,
    require_approval boolean NOT NULL DEFAULT false,
    prompts          jsonb,
    -- {"verified_only": true, "include_unlisted": false, "exclude": ["identifier", ...]}
    filter           jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    last_check_at    timestamptz,
    last_state       text NOT NULL DEFAULT '',
    last_detail      text NOT NULL DEFAULT '',
    UNIQUE (org_id, name)
);

ALTER TABLE software_policies
    ADD CONSTRAINT software_policies_auto_fk FOREIGN KEY (auto_policy_id) REFERENCES software_auto_policies(id) ON DELETE CASCADE;
CREATE INDEX software_policies_auto ON software_policies (auto_policy_id) WHERE auto_policy_id IS NOT NULL;
-- One app, one child, per all-apps policy.
CREATE UNIQUE INDEX software_policies_auto_package ON software_policies (auto_policy_id, package_id) WHERE auto_policy_id IS NOT NULL;

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON software_auto_policies TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
ALTER TABLE software_policies DROP CONSTRAINT IF EXISTS software_policies_auto_fk;
DROP INDEX IF EXISTS software_policies_auto_package, software_policies_auto;
DROP TABLE IF EXISTS software_auto_policies CASCADE;
ALTER TABLE software_policies
    DROP COLUMN IF EXISTS auto_policy_id, DROP COLUMN IF EXISTS last_deployment_id, DROP COLUMN IF EXISTS last_run_at,
    DROP COLUMN IF EXISTS last_detail, DROP COLUMN IF EXISTS last_state, DROP COLUMN IF EXISTS last_check_at;
