-- The mail server in the console (ADR-0053, slice 1): one row with the mail
-- server super administrators set in the console, if any, and the limits on
-- how much mail EasyRMM sends through whichever mail server is in force
-- (the console's, or EASYRMM_SMTP_* in .env, which wins); and a log of the
-- messages sent in the last 24 hours, which the limits count.

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
    from_name        text NOT NULL DEFAULT '' CHECK (length(from_name) <= 400),
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
-- count. account marks mail to people's own accounts (invitations, password
-- resets), which may use the whole day's limit; other mail stops at 90% of
-- it. Rows are taken under an advisory lock and removed after 24 hours.
CREATE TABLE mail_sends (
    id       bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sent_at  timestamptz NOT NULL DEFAULT clock_timestamp(),
    account  boolean NOT NULL
);
CREATE INDEX mail_sends_sent_at ON mail_sends (sent_at);

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

-- +goose Down
DROP TABLE IF EXISTS mail_sends;
DROP TABLE IF EXISTS mail_server;
