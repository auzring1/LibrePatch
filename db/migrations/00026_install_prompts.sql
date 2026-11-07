-- +goose Up
-- Optional messages to the signed-in user while software is installed (D124). Null/empty everywhere means what it always
-- meant: fully silent.

-- The programs an update replaces (image names such as "chrome.exe"), so a deployment can wait for them to be closed, ask the
-- user to close them, or close them.
ALTER TABLE package_overrides ADD COLUMN processes text[] NOT NULL DEFAULT '{}';

-- What a deployment or a policy chose: {"in_use": "ask", "ask_timeout_s": 300, "defer_minutes": 60, "restart": "ask",
-- "restart_notify_minutes": 5}. Null = silent.
ALTER TABLE deployments ADD COLUMN prompts jsonb;
ALTER TABLE software_policies ADD COLUMN prompts jsonb;

-- +goose Down
ALTER TABLE software_policies DROP COLUMN IF EXISTS prompts;
ALTER TABLE deployments DROP COLUMN IF EXISTS prompts;
ALTER TABLE package_overrides DROP COLUMN IF EXISTS processes;
