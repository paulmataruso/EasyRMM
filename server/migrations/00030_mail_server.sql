-- The mail server in the console (ADR-0053, slice 1): one row with the mail
-- server super administrators set in the console, if any, and the limits on
-- how much mail EasyRMM sends through whichever mail server is in force
-- (the console's, or EASYRMM_SMTP_* in .env, which wins); a log of the
-- messages sent in the last 24 hours, which the limits count; and the
-- account mail waiting for room under them.

-- +goose Up

CREATE TABLE mail_server (
    id               boolean PRIMARY KEY DEFAULT true CHECK (id),
    -- The console's mail server; an empty host means none is set here.
    host             text NOT NULL DEFAULT '' CHECK (length(host) <= 253),
    port             integer NOT NULL DEFAULT 587 CHECK (port BETWEEN 1 AND 65535),
    -- starttls: STARTTLS required; tls: TLS from the first byte; none: only
    -- to a relay on loopback, which the service checks.
    security         text NOT NULL DEFAULT 'starttls' CHECK (security IN ('starttls', 'tls', 'none')),
    -- How EasyRMM signs in: not at all, or with a user name and a password
    -- (sealed with EASYRMM_SECRET_KEY, bound to this column).
    sign_in          text NOT NULL DEFAULT 'none' CHECK (sign_in IN ('none', 'password')),
    username         text NOT NULL DEFAULT '' CHECK (length(username) <= 255),
    password_sealed  text NOT NULL DEFAULT '',
    from_address     text NOT NULL DEFAULT '' CHECK (length(from_address) <= 254),
    from_name        text NOT NULL DEFAULT '' CHECK (length(from_name) <= 100),
    -- Messages a minute and a day, through whichever mail server is in
    -- force. 30 a minute is Exchange Online's rate; 9,000 a day stays under
    -- its 10,000 recipients in 24 hours.
    per_minute       integer NOT NULL DEFAULT 30 CHECK (per_minute BETWEEN 1 AND 10000),
    per_day          integer NOT NULL DEFAULT 9000 CHECK (per_day BETWEEN 1 AND 1000000),
    -- The last test message, for its limit of one every 30 seconds.
    last_test_at     timestamptz,
    updated_at       timestamptz,
    updated_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    limits_updated_at timestamptz,
    limits_updated_by uuid REFERENCES users (id) ON DELETE SET NULL,
    CHECK (per_day >= per_minute),
    CHECK (host <> '' OR (sign_in = 'none' AND from_address = '' AND from_name = '')),
    CHECK (host = '' OR from_address <> ''),
    CHECK ((sign_in = 'password') = (username <> '')),
    CHECK ((sign_in = 'password') = (password_sealed <> ''))
);
-- The row always exists, so the limits hold before anyone sets them.
INSERT INTO mail_server (id) VALUES (true);

-- Each message sent, or being sent, in the last 24 hours: what the limits
-- count, and against whom (the numbers are in the service, mailserver).
-- kind is reset for a password reset the person asked for, which may use
-- the whole day's limit; admin for an invitation or a password link an
-- administrator sent (sent_by), which stops at 90% of it; and other for
-- the rest, which stops at 80%. account_id is the account an invitation
-- or password email went to, whoever asked; organization_id its
-- organization (null for none or several), and for admin mail null when a
-- super administrator sent it. Rows are taken under an advisory lock and
-- removed after 24 hours.
CREATE TABLE mail_sends (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sent_at         timestamptz NOT NULL DEFAULT clock_timestamp(),
    kind            text NOT NULL CHECK (kind IN ('reset', 'admin', 'other')),
    sent_by         uuid,
    organization_id uuid,
    account_id      uuid,
    CHECK (kind = 'admin' OR sent_by IS NULL),
    CHECK (kind <> 'other' OR (organization_id IS NULL AND account_id IS NULL))
);
CREATE INDEX mail_sends_sent_at ON mail_sends (sent_at);
CREATE INDEX mail_sends_sent_by ON mail_sends (sent_by, sent_at) WHERE kind = 'admin';
CREATE INDEX mail_sends_organization ON mail_sends (organization_id, sent_at) WHERE kind <> 'other';
CREATE INDEX mail_sends_account ON mail_sends (account_id, sent_at) WHERE account_id IS NOT NULL;

-- Account mail waiting for room under the minute's limit, on any of
-- EasyRMM's servers: other mail stands back while one waits. A server that
-- stops while waiting leaves a row that runs out at until.
CREATE TABLE mail_waits (
    id     bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    until  timestamptz NOT NULL
);

-- The mail server the patching engine is given, by the one of EasyRMM's
-- servers that gives it (holding a session advisory lock): an Argon2id
-- digest of it, with its salt, never the mail server itself, so that the
-- others can tell whether theirs is the same.
CREATE TABLE mail_engine_given (
    id        boolean PRIMARY KEY DEFAULT true CHECK (id),
    salt      bytea NOT NULL CHECK (length(salt) = 16),
    digest    bytea NOT NULL CHECK (length(digest) = 32),
    given_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Platform-wide: only platform-scope transactions see or change them.
ALTER TABLE mail_server ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_server FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_server_system ON mail_server TO easyrmm_app
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
CREATE POLICY mail_server_owner ON mail_server TO easyrmm_owner USING (true) WITH CHECK (true);
GRANT SELECT, UPDATE ON mail_server TO easyrmm_app;

ALTER TABLE mail_sends ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_sends FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_sends_system ON mail_sends TO easyrmm_app
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, DELETE ON mail_sends TO easyrmm_app;

ALTER TABLE mail_waits ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_waits FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_waits_system ON mail_waits TO easyrmm_app
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, DELETE ON mail_waits TO easyrmm_app;

ALTER TABLE mail_engine_given ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_engine_given FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_engine_given_system ON mail_engine_given TO easyrmm_app
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE ON mail_engine_given TO easyrmm_app;

-- +goose Down
DROP TABLE IF EXISTS mail_engine_given;
DROP TABLE IF EXISTS mail_waits;
DROP TABLE IF EXISTS mail_sends;
DROP TABLE IF EXISTS mail_server;
