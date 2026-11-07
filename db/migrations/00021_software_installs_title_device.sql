-- +goose Up
-- The Software page counts, per product, the devices that have it and the versions seen. With 5,000 devices that is
-- 600,000 install rows, and counting distinct devices over an unsorted heap sorted 40 MB on disk (about 0.95 s per page).
-- This index delivers the rows already ordered by (product, device), so PostgreSQL counts them in one pass without a
-- sort and without reading the table (version is stored in the index for the second count). It covers programs only:
-- the page's default view leaves system components out, and the query for that view repeats the condition.
CREATE INDEX software_installs_title_device ON software_installs (title_id, device_id) INCLUDE (version) WHERE NOT system_component;

-- +goose Down
DROP INDEX IF EXISTS software_installs_title_device;
