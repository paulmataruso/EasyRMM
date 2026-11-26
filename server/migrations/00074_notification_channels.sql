-- ADR-0053 slice 3: notification channels (email and generic webhooks), the
-- sender's outbox, notices, the journal for notices, and the address
-- policy's approvals. Every table has row-level security forced.
--
-- The nil UUID is the platform's owner key: rbac.Principal.Can reads the nil
-- UUID as the platform, so no organization may have it.

-- +goose Up
ALTER TABLE organizations ADD CONSTRAINT organizations_id_not_nil CHECK (id <> '00000000-0000-0000-0000-000000000000');

-- What an organization may see of a shared channel: owner, kind, name, on or
-- off. Everything else is in notification_channel_details.
CREATE TABLE notification_channels (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- NULL for the platform's channels.
    organization_id uuid REFERENCES organizations (id) ON DELETE CASCADE,
    -- The owner key, never NULL: the organization's ID, or the nil UUID.
    owner           uuid NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('email', 'webhook')),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    enabled         boolean NOT NULL DEFAULT true,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT notification_channels_org_not_nil CHECK (organization_id IS NULL OR organization_id <> '00000000-0000-0000-0000-000000000000'),
    CONSTRAINT notification_channels_owner CHECK (owner = coalesce(organization_id, '00000000-0000-0000-0000-000000000000')),
    CONSTRAINT notification_channels_id_owner UNIQUE (id, owner)
);
CREATE UNIQUE INDEX notification_channels_name ON notification_channels (owner, lower(name));
CREATE TRIGGER notification_channels_touch BEFORE UPDATE ON notification_channels
    FOR EACH ROW EXECUTE FUNCTION easyrmm_touch_updated_at();

-- Platform channels shared with organizations. Nothing is shared by default.
CREATE TABLE notification_channel_shares (
    channel_id      uuid NOT NULL,
    owner           uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'
                    CHECK (owner = '00000000-0000-0000-0000-000000000000'),
    organization_id uuid NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    shared_by       uuid,
    shared_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (channel_id, organization_id),
    FOREIGN KEY (channel_id, owner) REFERENCES notification_channels (id, owner) ON DELETE CASCADE
);
CREATE INDEX notification_channel_shares_org ON notification_channel_shares (organization_id);

-- What only the owner sees: recipients, the destination, the sealed URL and
-- signing secret, the failing state and the transport's generation. Its own
-- owner column carries its own policy: no EXISTS on channels, no exception
-- for platform rows.
CREATE TABLE notification_channel_details (
    channel_id        uuid PRIMARY KEY,
    owner             uuid NOT NULL,
    recipients        text[] NOT NULL DEFAULT '{}' CHECK (cardinality(recipients) <= 20),
    -- The host and port of a webhook's URL, plain: lists show the host only.
    webhook_host      text CHECK (webhook_host IS NULL OR length(webhook_host) BETWEEN 1 AND 253),
    webhook_port      integer CHECK (webhook_port IS NULL OR webhook_port BETWEEN 1 AND 65535),
    -- Sealed with EASYRMM_SECRET_KEY, bound to the channel and the field.
    sealed_url        text,
    sealed_secret     text,
    -- PEM of the one certificate authority to trust, for a private receiver.
    trusted_authority text CHECK (trusted_authority IS NULL OR length(trusted_authority) <= 32768),
    -- A channel moved from the engine also sends X-EasyPatch-*; it can only be turned off.
    legacy_headers    boolean NOT NULL DEFAULT false,
    failing_since     timestamptz,
    -- Failing: a delivery failed for 15 minutes without a success since, was given up, or was
    -- answered permanently (401, 403, 404, 410). It recovers at the next success. Tests do not count.
    failing           boolean NOT NULL DEFAULT false,
    last_error        text CHECK (last_error IS NULL OR length(last_error) <= 500),
    last_success_at   timestamptz,
    last_attempt_at   timestamptz,
    -- Any change of host, port, approval, authority or policy increases it,
    -- and with it the transport is made anew.
    generation        bigint NOT NULL DEFAULT 1,
    -- Messages that failed in a row; three mark the channel failing.
    failures_in_row   integer NOT NULL DEFAULT 0,
    FOREIGN KEY (channel_id, owner) REFERENCES notification_channels (id, owner) ON DELETE CASCADE
);

-- A private destination a super administrator has to approve. One row per
-- channel: its host and port, the addresses proposed when approval was asked,
-- and the prefixes approved.
CREATE TABLE notification_channel_approvals (
    channel_id   uuid PRIMARY KEY,
    owner        uuid NOT NULL,
    host         text NOT NULL,
    port         integer NOT NULL,
    proposed     text[] NOT NULL DEFAULT '{}',
    prefixes     text[] NOT NULL DEFAULT '{}',
    state        text NOT NULL DEFAULT 'requested' CHECK (state IN ('requested', 'approved')),
    requested_by uuid,
    requested_at timestamptz NOT NULL DEFAULT now(),
    approved_by  uuid,
    approved_at  timestamptz,
    CHECK ((state = 'approved') = (approved_at IS NOT NULL AND cardinality(prefixes) > 0)),
    FOREIGN KEY (channel_id, owner) REFERENCES notification_channels (id, owner) ON DELETE CASCADE
);

-- The outbox.
CREATE TABLE notification_deliveries (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner         uuid NOT NULL,
    -- The organization charged, the nil UUID for the platform's own.
    charged_org   uuid NOT NULL,
    channel_id    uuid,
    kind          text NOT NULL CHECK (kind IN ('digest', 'event', 'report', 'test')),
    event         text NOT NULL CHECK (length(event) BETWEEN 1 AND 64),
    -- What order is kept for: notices (and later alerts' incidents and site outages).
    subjects      text[] NOT NULL DEFAULT '{}',
    -- The organizations the delivery is about.
    about         uuid[] NOT NULL DEFAULT '{}',
    message       jsonb NOT NULL,
    status        text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'dropped')),
    attempts      integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    lease_until   timestamptz,
    -- EasyRMM's own sentence, never a URL's path or query, never a response body.
    last_error    text CHECK (last_error IS NULL OR length(last_error) <= 500),
    -- The mail server's reply, for super administrators only.
    last_reply    text CHECK (last_reply IS NULL OR length(last_reply) <= 500),
    -- A webhook's 413 splits its delivery once.
    split         boolean NOT NULL DEFAULT false,
    queued_at     timestamptz NOT NULL DEFAULT now(),
    ended_at      timestamptz,
    CONSTRAINT notification_deliveries_owner_about CHECK (owner = '00000000-0000-0000-0000-000000000000' OR about <@ ARRAY[owner]),
    CONSTRAINT notification_deliveries_owner_charged CHECK (owner = '00000000-0000-0000-0000-000000000000' OR charged_org = owner),
    CONSTRAINT notification_deliveries_ended CHECK ((status IN ('pending')) = (ended_at IS NULL)),
    FOREIGN KEY (channel_id, owner) REFERENCES notification_channels (id, owner) ON DELETE SET NULL (channel_id)
);
CREATE INDEX notification_deliveries_due ON notification_deliveries (channel_id, queued_at, id) WHERE status = 'pending';
CREATE INDEX notification_deliveries_charged ON notification_deliveries (charged_org, queued_at) WHERE status = 'pending';
CREATE INDEX notification_deliveries_ended ON notification_deliveries (ended_at) WHERE ended_at IS NOT NULL;

CREATE TABLE notification_delivery_recipients (
    delivery_id uuid NOT NULL REFERENCES notification_deliveries (id) ON DELETE CASCADE,
    recipient   text NOT NULL,
    status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    attempts    integer NOT NULL DEFAULT 0,
    error       text CHECK (error IS NULL OR length(error) <= 500),
    reply       text CHECK (reply IS NULL OR length(reply) <= 500),
    sent_at     timestamptz,
    PRIMARY KEY (delivery_id, recipient)
);
CREATE INDEX notification_delivery_recipients_sent ON notification_delivery_recipients (sent_at) WHERE sent_at IS NOT NULL;

-- Each organization's quotas, when not the defaults (20 channels, 50 rules, 20
-- tests an hour, 600 messages an hour).
CREATE TABLE notification_quotas (
    organization_id uuid PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    channels        integer NOT NULL DEFAULT 20 CHECK (channels BETWEEN 0 AND 10000),
    rules           integer NOT NULL DEFAULT 50 CHECK (rules BETWEEN 0 AND 10000),
    tests_per_hour  integer NOT NULL DEFAULT 20 CHECK (tests_per_hour BETWEEN 0 AND 10000),
    messages_per_hour integer NOT NULL DEFAULT 600 CHECK (messages_per_hour BETWEEN 0 AND 1000000),
    updated_by      uuid,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- Notices: what the console raises that is not a policy's condition on a
-- device. Opened and resolved by the server at platform scope; people
-- acknowledge them in their own scope.
CREATE TABLE notices (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES organizations (id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]{1,62}$'),
    -- What the notice is about (a channel's ID, say): one is open for each.
    subject         text NOT NULL CHECK (length(subject) <= 128),
    site_id         uuid REFERENCES sites (id) ON DELETE SET NULL,
    device_id       uuid REFERENCES devices (id) ON DELETE SET NULL,
    title           text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    detail          text NOT NULL DEFAULT '' CHECK (length(detail) <= 1000),
    opened_at       timestamptz NOT NULL DEFAULT now(),
    acknowledged_at timestamptz,
    acknowledged_by uuid,
    resolved_at     timestamptz
);
CREATE UNIQUE INDEX notices_open ON notices (coalesce(organization_id, '00000000-0000-0000-0000-000000000000'), kind, subject)
    WHERE resolved_at IS NULL;
CREATE INDEX notices_org ON notices (organization_id, opened_at DESC);

-- The journal, written by the database: a row for each notice opened,
-- acknowledged or resolved, in the transaction that makes the change. The
-- trigger copies NEW and OLD and reads no other table; the journal has no
-- foreign key, CHECK or unique index a copied row could fail.
CREATE TABLE notification_events (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    subject_type text NOT NULL,
    subject_id   uuid NOT NULL,
    event        text NOT NULL,
    old_row      jsonb,
    new_row      jsonb,
    created_at   timestamptz NOT NULL DEFAULT now(),
    status       text NOT NULL DEFAULT 'new',
    planned_at   timestamptz,
    failed_runs  integer NOT NULL DEFAULT 0,
    error        text
);
CREATE INDEX notification_events_new ON notification_events (id) WHERE status <> 'planned';
CREATE INDEX notification_events_planned ON notification_events (planned_at) WHERE status = 'planned';

-- +goose StatementBegin
CREATE FUNCTION easyrmm_notice_journal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO notification_events (subject_type, subject_id, event, new_row)
        VALUES ('notice', NEW.id, 'opened', to_jsonb(NEW));
    ELSIF NEW.resolved_at IS DISTINCT FROM OLD.resolved_at THEN
        INSERT INTO notification_events (subject_type, subject_id, event, old_row, new_row)
        VALUES ('notice', NEW.id, CASE WHEN NEW.resolved_at IS NULL THEN 'reopened' ELSE 'resolved' END, to_jsonb(OLD), to_jsonb(NEW));
    ELSE
        INSERT INTO notification_events (subject_type, subject_id, event, old_row, new_row)
        VALUES ('notice', NEW.id, 'acknowledged', to_jsonb(OLD), to_jsonb(NEW));
    END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION easyrmm_notice_journal() FROM PUBLIC;

CREATE TRIGGER notices_journal_insert AFTER INSERT ON notices
    FOR EACH ROW EXECUTE FUNCTION easyrmm_notice_journal();
CREATE TRIGGER notices_journal_update AFTER UPDATE ON notices
    FOR EACH ROW WHEN (OLD.resolved_at IS DISTINCT FROM NEW.resolved_at OR OLD.acknowledged_at IS DISTINCT FROM NEW.acknowledged_at)
    EXECUTE FUNCTION easyrmm_notice_journal();

-- Row-level security.
ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_channels_read ON notification_channels FOR SELECT USING (
    easyrmm_scope_all()
    OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    OR (owner = '00000000-0000-0000-0000-000000000000' AND EXISTS (
        SELECT 1 FROM notification_channel_shares s
        WHERE s.channel_id = notification_channels.id
          AND s.organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))))
);
CREATE POLICY notification_channels_write ON notification_channels FOR ALL
    USING (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    WITH CHECK (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));

ALTER TABLE notification_channel_shares ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channel_shares FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_channel_shares_read ON notification_channel_shares FOR SELECT
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
CREATE POLICY notification_channel_shares_write ON notification_channel_shares FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE notification_channel_details ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channel_details FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_channel_details_all ON notification_channel_details FOR ALL
    USING (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    WITH CHECK (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));

ALTER TABLE notification_channel_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channel_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_channel_approvals_read ON notification_channel_approvals FOR SELECT
    USING (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
-- An organization's scope may only ask; approving and withdrawing are at platform scope.
CREATE POLICY notification_channel_approvals_ask ON notification_channel_approvals FOR INSERT
    WITH CHECK (easyrmm_scope_all() OR (owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')) AND state = 'requested'));
CREATE POLICY notification_channel_approvals_update ON notification_channel_approvals FOR UPDATE
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY notification_channel_approvals_delete ON notification_channel_approvals FOR DELETE
    USING (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));

ALTER TABLE notification_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_deliveries_read ON notification_deliveries FOR SELECT
    USING (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
-- An organization's scope inserts only its own tests.
CREATE POLICY notification_deliveries_insert ON notification_deliveries FOR INSERT
    WITH CHECK (easyrmm_scope_all() OR (owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')) AND kind = 'test'));
CREATE POLICY notification_deliveries_update ON notification_deliveries FOR UPDATE
    USING (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')))
    WITH CHECK (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));
CREATE POLICY notification_deliveries_delete ON notification_deliveries FOR DELETE
    USING (easyrmm_scope_all() OR owner = ANY (easyrmm_scope_ids('easyrmm.scope_orgs')));

ALTER TABLE notification_delivery_recipients ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_delivery_recipients FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_delivery_recipients_all ON notification_delivery_recipients FOR ALL
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM notification_deliveries d WHERE d.id = delivery_id))
    WITH CHECK (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM notification_deliveries d WHERE d.id = delivery_id));

ALTER TABLE notification_quotas ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_quotas FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_quotas_all ON notification_quotas FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());

ALTER TABLE notices ENABLE ROW LEVEL SECURITY;
ALTER TABLE notices FORCE ROW LEVEL SECURITY;
CREATE POLICY notices_read ON notices FOR SELECT USING (
    easyrmm_scope_all()
    OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
    OR (site_id IS NOT NULL AND site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites')))
);
CREATE POLICY notices_insert ON notices FOR INSERT WITH CHECK (easyrmm_scope_all());
CREATE POLICY notices_delete ON notices FOR DELETE USING (easyrmm_scope_all());
CREATE POLICY notices_ack ON notices FOR UPDATE
    USING (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
           OR (site_id IS NOT NULL AND site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))))
    WITH CHECK (easyrmm_scope_all() OR organization_id = ANY (easyrmm_scope_ids('easyrmm.scope_orgs'))
           OR (site_id IS NOT NULL AND site_id = ANY (easyrmm_scope_ids('easyrmm.scope_sites'))));

-- The journal: inserted only by the trigger's function (the owner), read and
-- planned at platform scope only. The runtime role has no INSERT.
ALTER TABLE notification_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_events FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_events_owner ON notification_events FOR INSERT TO easyrmm_owner WITH CHECK (true);
CREATE POLICY notification_events_read ON notification_events FOR SELECT USING (easyrmm_scope_all());
CREATE POLICY notification_events_plan ON notification_events FOR UPDATE USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY notification_events_purge ON notification_events FOR DELETE USING (easyrmm_scope_all());

GRANT SELECT, INSERT, UPDATE, DELETE ON notification_channels, notification_channel_shares, notification_channel_details,
    notification_channel_approvals, notification_deliveries, notification_delivery_recipients, notification_quotas, notices
    TO easyrmm_app;
GRANT SELECT, DELETE ON notification_events TO easyrmm_app;
GRANT UPDATE (status, planned_at, failed_runs, error) ON notification_events TO easyrmm_app;

-- +goose Down
SELECT set_config('easyrmm.scope_all', 'on', true);
DROP TRIGGER IF EXISTS notices_journal_update ON notices;
DROP TRIGGER IF EXISTS notices_journal_insert ON notices;
DROP FUNCTION IF EXISTS easyrmm_notice_journal();
DROP TABLE IF EXISTS notification_events, notices, notification_quotas, notification_delivery_recipients,
    notification_deliveries, notification_channel_approvals, notification_channel_details,
    notification_channel_shares, notification_channels CASCADE;
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS organizations_id_not_nil;
