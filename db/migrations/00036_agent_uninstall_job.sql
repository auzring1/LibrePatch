-- +goose Up
-- Revoking a device can first tell the agent to uninstall itself (D158).
ALTER TABLE jobs DROP CONSTRAINT jobs_type_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_type_check CHECK (type IN
    ('software_install', 'software_uninstall', 'software_update', 'inventory_full', 'wu_scan', 'wu_install', 'wu_hide', 'reboot', 'agent_update',
     'wake', 'inspect', 'run_script', 'profile_delete', 'agent_uninstall'));

-- +goose Down
DELETE FROM jobs WHERE type = 'agent_uninstall';
ALTER TABLE jobs DROP CONSTRAINT jobs_type_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_type_check CHECK (type IN
    ('software_install', 'software_uninstall', 'software_update', 'inventory_full', 'wu_scan', 'wu_install', 'wu_hide', 'reboot', 'agent_update',
     'wake', 'inspect', 'run_script', 'profile_delete'));
