-- +goose Up
-- Software policies can roll a new version out through the update rings (the same rings Windows updates use, D60) and can
-- wait for an administrator to approve each new version first (D121).
ALTER TABLE software_policies
    ADD COLUMN use_rings        boolean NOT NULL DEFAULT false,
    ADD COLUMN require_approval boolean NOT NULL DEFAULT false;

-- An administrator's decision about one version of one package. No row = waiting for a decision. The decision is the
-- organization's, not the policy's: approving a version approves it for every policy that needs approval for it.
CREATE TABLE software_approvals (
    org_id     uuid NOT NULL REFERENCES organizations(id),
    package_id uuid NOT NULL REFERENCES catalog_packages(id) ON DELETE CASCADE,
    version    text NOT NULL,
    decision   text NOT NULL CHECK (decision IN ('approved', 'declined')),
    note       text NOT NULL DEFAULT '' CHECK (length(note) <= 1000),
    decided_by uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, package_id, version)
);

-- A ring that failed its success threshold for a version stops that version from reaching later rings until an
-- administrator releases the hold (the software twin of wu_holds).
CREATE TABLE software_holds (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations(id),
    policy_id   uuid NOT NULL REFERENCES software_policies(id) ON DELETE CASCADE,
    version     text NOT NULL,
    ring_id     uuid NOT NULL REFERENCES wu_rings(id) ON DELETE CASCADE,
    reason      text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    released_at timestamptz,
    released_by uuid REFERENCES users(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX software_holds_open ON software_holds (policy_id, version, ring_id) WHERE released_at IS NULL;
CREATE INDEX software_holds_policy ON software_holds (policy_id, version);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON software_approvals, software_holds TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS software_holds, software_approvals CASCADE;
ALTER TABLE software_policies DROP COLUMN IF EXISTS require_approval, DROP COLUMN IF EXISTS use_rings;
