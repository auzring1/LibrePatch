-- +goose Up
-- Removing a user's profile from a device is a job of its own (D157).
ALTER TABLE jobs DROP CONSTRAINT jobs_type_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_type_check CHECK (type IN
    ('software_install', 'software_uninstall', 'software_update', 'inventory_full', 'wu_scan', 'wu_install', 'wu_hide', 'reboot', 'agent_update',
     'wake', 'inspect', 'run_script', 'profile_delete'));

-- +goose Down
DELETE FROM jobs WHERE type = 'profile_delete';
ALTER TABLE jobs DROP CONSTRAINT jobs_type_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_type_check CHECK (type IN
    ('software_install', 'software_uninstall', 'software_update', 'inventory_full', 'wu_scan', 'wu_install', 'wu_hide', 'reboot', 'agent_update',
     'wake', 'inspect', 'run_script'));
