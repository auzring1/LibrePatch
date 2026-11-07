-- +goose Up
-- Phase 5: software policies. "Keep this package at its newest approved version on these groups"
-- and "install this package on newly enrolled devices of these groups".

CREATE TABLE software_policies (
    id                   uuid PRIMARY KEY,
    org_id               uuid NOT NULL REFERENCES organizations(id),
    name                 text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    kind                 text NOT NULL CHECK (kind IN ('keep_updated', 'baseline')),
    package_id           uuid NOT NULL REFERENCES catalog_packages(id) ON DELETE CASCADE,
    group_ids            uuid[] NOT NULL CHECK (cardinality(group_ids) BETWEEN 1 AND 50),
    delay_days           integer NOT NULL DEFAULT 0 CHECK (delay_days BETWEEN 0 AND 365),  -- after the version was imported
    only_new_devices     boolean NOT NULL DEFAULT true,   -- baseline: only devices enrolled after the policy was created
    unverified_confirmed boolean NOT NULL DEFAULT false,  -- the administrator accepted an unverified winget package
    maint_window         jsonb,
    enabled              boolean NOT NULL DEFAULT true,
    created_by           uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

-- The latest attempt of a policy on a device, so one device is not deployed to over and over.
CREATE TABLE policy_attempts (
    policy_id     uuid NOT NULL REFERENCES software_policies(id) ON DELETE CASCADE,
    device_id     uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    version       text NOT NULL,
    deployment_id uuid REFERENCES deployments(id) ON DELETE SET NULL,
    failures      integer NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL,
    PRIMARY KEY (policy_id, device_id)
);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON software_policies, policy_attempts TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS policy_attempts, software_policies CASCADE;
