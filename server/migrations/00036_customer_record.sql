-- The customer record (ADR-0066, slice 1, first pull request): an
-- organization's main phone, email, website and business hours; each site's
-- address as fields beside the free-text one, and its own hours; contacts at
-- the organization or one of its sites; places within a site (a building, a
-- floor, a room, a rack). Read with doc.view and written with doc.manage,
-- which the server checks; row-level security keeps each organization's
-- rows to it, and site-scoped people to their sites' rows.

-- +goose Up

-- ---------------------------------------------------------------------------
-- Organizations and sites
-- ---------------------------------------------------------------------------

-- business_hours is a weekly schedule the server validates (up to four
-- intervals a day, each a start and an end in local time); NULL when none
-- is kept. A site without its own uses its organization's, in the site's
-- time zone. after_hours_note says what to do outside them.
ALTER TABLE organizations
    ADD COLUMN main_phone       text NOT NULL DEFAULT '' CHECK (length(main_phone) <= 50),
    ADD COLUMN main_email       text NOT NULL DEFAULT '' CHECK (length(main_email) <= 254),
    ADD COLUMN website          text NOT NULL DEFAULT '' CHECK (length(website) <= 2000),
    ADD COLUMN business_hours   jsonb CHECK (jsonb_typeof(business_hours) = 'object' AND pg_column_size(business_hours) <= 8192),
    ADD COLUMN after_hours_note text NOT NULL DEFAULT '' CHECK (length(after_hours_note) <= 2000);

-- The address as fields; the free-text address stays beside them for
-- addresses that fit no fields, and nothing is parsed from it.
-- country_code is an ISO 3166-1 alpha-2 code, checked against the list in
-- the server.
ALTER TABLE sites
    ADD COLUMN address_line1    text NOT NULL DEFAULT '' CHECK (length(address_line1) <= 200),
    ADD COLUMN address_line2    text NOT NULL DEFAULT '' CHECK (length(address_line2) <= 200),
    ADD COLUMN city             text NOT NULL DEFAULT '' CHECK (length(city) <= 100),
    ADD COLUMN region           text NOT NULL DEFAULT '' CHECK (length(region) <= 100),
    ADD COLUMN postal_code      text NOT NULL DEFAULT '' CHECK (length(postal_code) <= 20),
    ADD COLUMN country_code     text NOT NULL DEFAULT '' CHECK (country_code ~ '^([A-Z]{2})?$'),
    ADD COLUMN business_hours   jsonb CHECK (jsonb_typeof(business_hours) = 'object' AND pg_column_size(business_hours) <= 8192),
    ADD COLUMN after_hours_note text NOT NULL DEFAULT '' CHECK (length(after_hours_note) <= 2000);

-- Time zones: from now on the server takes only the names in the IANA
-- database, as the database writes them. Before, it took any name it could
-- open, so "Europe//London", "Europe/./London" or "./Europe/London" may be
-- stored for Europe/London: each becomes the name it stood for. Down leaves
-- them so, since they are the same zones. Both tables force row-level
-- security, on their owner too.
SELECT set_config('easyrmm.scope_all', 'on', true);
UPDATE organizations SET timezone = ltrim(regexp_replace(regexp_replace(timezone, '(^|/)\.(?=/|$)', '', 'g'), '/{2,}', '/', 'g'), '/')
    WHERE timezone ~ '//|(^|/)\.(/|$)';
UPDATE sites SET timezone = ltrim(regexp_replace(regexp_replace(timezone, '(^|/)\.(?=/|$)', '', 'g'), '/{2,}', '/', 'g'), '/')
    WHERE timezone ~ '//|(^|/)\.(/|$)';

-- ---------------------------------------------------------------------------
-- Places within a site
-- ---------------------------------------------------------------------------

-- depth is 1 for a place at the top of its site and its parent's plus one
-- below, at most 4. The key on (site_id, parent_id, parent_depth) makes the
-- database keep it so: a parent is in the same site, one level up, which
-- also rules out a place inside itself. Moving a place moves its places
-- with it, in one statement, so the key holds at its end.
CREATE TABLE site_places (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    site_id         uuid NOT NULL,
    parent_id       uuid,
    depth           smallint NOT NULL CHECK (depth BETWEEN 1 AND 4),
    parent_depth    smallint GENERATED ALWAYS AS (CASE WHEN parent_id IS NULL THEN NULL ELSE depth - 1 END) STORED,
    kind            text NOT NULL CHECK (kind IN ('building', 'floor', 'room', 'rack', 'other')),
    name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CHECK ((parent_id IS NULL) = (depth = 1)),
    UNIQUE (site_id, id, depth),
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (site_id, parent_id, parent_depth) REFERENCES site_places (site_id, id, depth)
);
-- Two places of one name in the same place would be told apart by nothing.
CREATE UNIQUE INDEX site_places_name_key ON site_places (site_id, parent_id, lower(name)) NULLS NOT DISTINCT;
CREATE INDEX site_places_org_idx ON site_places (organization_id);
CREATE INDEX site_places_parent_idx ON site_places (parent_id) WHERE parent_id IS NOT NULL;
CREATE TRIGGER site_places_touch BEFORE UPDATE ON site_places
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

-- ---------------------------------------------------------------------------
-- Contacts
-- ---------------------------------------------------------------------------

-- Customers' staff, not EasyRMM accounts, at the organization (site_id
-- NULL) or one of its sites. priority is primary, secondary or none;
-- emergency is apart, since an emergency contact can also be primary. At
-- most one primary at the organization's level and one per site.
CREATE TABLE contacts (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    site_id         uuid,
    name            text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    job_title       text NOT NULL DEFAULT '' CHECK (length(job_title) <= 200),
    email           text NOT NULL DEFAULT '' CHECK (length(email) <= 254),
    office_phone    text NOT NULL DEFAULT '' CHECK (length(office_phone) <= 50),
    mobile_phone    text NOT NULL DEFAULT '' CHECK (length(mobile_phone) <= 50),
    note            text NOT NULL DEFAULT '' CHECK (length(note) <= 2000),
    priority        text NOT NULL DEFAULT 'none' CHECK (priority IN ('primary', 'secondary', 'none')),
    emergency       boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, site_id) REFERENCES sites (organization_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX contacts_primary_org_key ON contacts (organization_id) WHERE priority = 'primary' AND site_id IS NULL;
CREATE UNIQUE INDEX contacts_primary_site_key ON contacts (site_id) WHERE priority = 'primary';
CREATE INDEX contacts_org_idx ON contacts (organization_id);
CREATE INDEX contacts_site_idx ON contacts (site_id) WHERE site_id IS NOT NULL;
CREATE TRIGGER contacts_touch BEFORE UPDATE ON contacts
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

-- ---------------------------------------------------------------------------
-- Row-level security: sites_tenant's policy, without scope_read_orgs, so
-- that site-scoped people see their sites' rows and none of the
-- organization's own.
-- ---------------------------------------------------------------------------

ALTER TABLE site_places ENABLE ROW LEVEL SECURITY;
ALTER TABLE site_places FORCE ROW LEVEL SECURITY;
CREATE POLICY site_places_tenant ON site_places
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    )
    WITH CHECK (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );

ALTER TABLE contacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE contacts FORCE ROW LEVEL SECURITY;
CREATE POLICY contacts_tenant ON contacts
    USING (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    )
    WITH CHECK (
        easyrmm_scope_all()
        OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
        OR site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON site_places, contacts TO easyrmm_app;

-- +goose Down
DROP TABLE contacts;
DROP TABLE site_places;
ALTER TABLE sites
    DROP COLUMN after_hours_note,
    DROP COLUMN business_hours,
    DROP COLUMN country_code,
    DROP COLUMN postal_code,
    DROP COLUMN region,
    DROP COLUMN city,
    DROP COLUMN address_line2,
    DROP COLUMN address_line1;
ALTER TABLE organizations
    DROP COLUMN after_hours_note,
    DROP COLUMN business_hours,
    DROP COLUMN website,
    DROP COLUMN main_email,
    DROP COLUMN main_phone;
