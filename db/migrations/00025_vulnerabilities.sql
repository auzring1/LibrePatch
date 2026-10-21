-- +goose Up
-- Known vulnerabilities (D123). CVE data is public and the same for everyone, so these three tables carry no organization;
-- what is matched against it (the fleet's inventory) and the product mapping are the organization's.

CREATE TABLE cves (
    id             text PRIMARY KEY CHECK (id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    published      timestamptz,
    modified       timestamptz,
    summary        text NOT NULL DEFAULT '' CHECK (length(summary) <= 2000),
    cvss           real CHECK (cvss IS NULL OR (cvss >= 0 AND cvss <= 10)),
    severity       text NOT NULL DEFAULT '' CHECK (severity IN ('', 'low', 'medium', 'high', 'critical')),
    -- The CISA catalog of vulnerabilities known to be exploited.
    kev            boolean NOT NULL DEFAULT false,
    kev_name       text NOT NULL DEFAULT '' CHECK (length(kev_name) <= 600),
    kev_added      date,
    kev_due        date,
    kev_ransomware boolean NOT NULL DEFAULT false,
    kev_action     text NOT NULL DEFAULT '' CHECK (length(kev_action) <= 1000)
);
CREATE INDEX cves_kev ON cves (id) WHERE kev;

-- The versions of a product a CVE affects. Versions are stored as sortable keys (internal/shared/vercmp) so a range test is a
-- byte comparison in SQL; the original text is kept for display ("fixed in 130.0.6723.58").
CREATE TABLE cve_ranges (
    cve_id     text NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    vendor     text NOT NULL,
    product    text NOT NULL,
    start_key  bytea,
    start_incl boolean NOT NULL DEFAULT true,
    start_text text NOT NULL DEFAULT '',
    end_key    bytea,
    end_incl   boolean NOT NULL DEFAULT false,
    end_text   text NOT NULL DEFAULT ''
);
CREATE INDEX cve_ranges_product ON cve_ranges (vendor, product);
CREATE INDEX cve_ranges_cve ON cve_ranges (cve_id);

-- How an installed program is looked up in the CVE data: its normalized name (what inventory calls it) to a CPE vendor and
-- product. 'builtin' rows come with the product and can be switched off; 'user' rows are the administrator's.
CREATE TABLE cve_products (
    id              uuid PRIMARY KEY,
    org_id          uuid NOT NULL REFERENCES organizations(id),
    normalized_name text NOT NULL CHECK (length(normalized_name) BETWEEN 1 AND 200),
    vendor          text NOT NULL CHECK (length(vendor) BETWEEN 1 AND 100),
    product         text NOT NULL CHECK (length(product) BETWEEN 1 AND 100),
    source          text NOT NULL CHECK (source IN ('builtin', 'user')),
    enabled         boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, normalized_name, vendor, product)
);
CREATE INDEX cve_products_name ON cve_products (org_id, normalized_name) WHERE enabled;

-- What was last fetched from each feed ('kev', or 'nvd:<vendor>:<product>').
CREATE TABLE vuln_feeds (
    feed         text PRIMARY KEY,
    last_ok      timestamptz,
    last_attempt timestamptz,
    status       text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'ok', 'error')),
    last_error   text NOT NULL DEFAULT '' CHECK (length(last_error) <= 500),
    etag         text NOT NULL DEFAULT '' CHECK (length(etag) <= 200),
    items        integer NOT NULL DEFAULT 0
);

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'librepatch_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON cves, cve_ranges, cve_products, vuln_feeds TO librepatch_app;
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE IF EXISTS vuln_feeds, cve_products, cve_ranges, cves CASCADE;
