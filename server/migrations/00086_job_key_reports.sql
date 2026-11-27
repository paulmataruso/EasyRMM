-- ADR-0057 slice 1: what each device reports of the keys it trusts, the
-- instructions the server signed, what the agents say they accepted, and the
-- restores the server knows of.
--
--   devices, retired_devices   the last report of the keys the device trusts
--                              (each key with its generation), when it was
--                              signed, the build it came with, when the device
--                              first sent one, the cut-over the server sent
--                              it (set by slice 2), and the authorities in
--                              the ca.pem it loaded. A removed device keeps
--                              its last report.
--   device_unknown_keys        a key a device reports that this server never
--                              held: "Trusts an unknown key". Follows the
--                              device.
--   issued_instructions        everything the server signed for a device:
--                              kind, ID, device, the generation of the key
--                              that signed it, and when. Appended in the
--                              transaction that signs; never updated; no
--                              foreign key, so removing a device keeps them;
--                              kept 90 days. Follows the device.
--   device_instruction_log     the sequence of the device's instruction log
--                              this server recorded, and what a claim that the
--                              server acknowledged more did. Follows the device.
--   device_instruction_flags   an entry of a device's log that matches nothing
--                              the server issued: "Ran instructions this
--                              server never issued". Follows the device.
--   server_restores            when the server was restored from a backup, as
--                              the host's `incident restored` records it, and
--                              the possible restores devices' claims suggest.
--                              The deployment's.
--
-- Written by the server with the system scope; read like any device field.

-- +goose Up
ALTER TABLE devices
    ADD COLUMN job_keys_report            jsonb CHECK (job_keys_report IS NULL OR jsonb_typeof(job_keys_report) = 'array'),
    ADD COLUMN job_keys_report_at         timestamptz,
    ADD COLUMN job_keys_report_sha        text CHECK (job_keys_report_sha IS NULL OR length(job_keys_report_sha) <= 64),
    ADD COLUMN job_keys_first_reported_at timestamptz,
    ADD COLUMN job_key_cutover_generation bigint CHECK (job_key_cutover_generation IS NULL OR job_key_cutover_generation >= 1),
    ADD COLUMN job_key_cutover_at         timestamptz,
    -- The generation of the key enrollment (or a heartbeat answer of a build
    -- that cannot follow) gave the device: NULL for devices enrolled before
    -- the ring, which got generation 1.
    ADD COLUMN job_key_given_generation   bigint CHECK (job_key_given_generation IS NULL OR job_key_given_generation >= 1),
    ADD COLUMN agent_authorities          text[],
    ADD COLUMN agent_authorities_at       timestamptz;

ALTER TABLE retired_devices
    ADD COLUMN job_keys_report            jsonb CHECK (job_keys_report IS NULL OR jsonb_typeof(job_keys_report) = 'array'),
    ADD COLUMN job_keys_report_at         timestamptz,
    ADD COLUMN job_keys_report_sha        text CHECK (job_keys_report_sha IS NULL OR length(job_keys_report_sha) <= 64),
    ADD COLUMN job_keys_first_reported_at timestamptz,
    ADD COLUMN job_key_cutover_generation bigint CHECK (job_key_cutover_generation IS NULL OR job_key_cutover_generation >= 1),
    ADD COLUMN job_key_cutover_at         timestamptz,
    ADD COLUMN job_key_given_generation   bigint CHECK (job_key_given_generation IS NULL OR job_key_given_generation >= 1);

CREATE TABLE device_unknown_keys (
    device_id       uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    fingerprint     text NOT NULL CHECK (length(fingerprint) = 32),
    public_key      bytea NOT NULL CHECK (length(public_key) = 32),
    generation      bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, fingerprint)
);

CREATE TABLE issued_instructions (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind           text NOT NULL CHECK (length(kind) BETWEEN 1 AND 16),
    instruction_id text NOT NULL CHECK (length(instruction_id) BETWEEN 1 AND 200),
    device_id      uuid NOT NULL,
    generation     bigint NOT NULL CHECK (generation >= 1),
    issued_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX issued_instructions_lookup ON issued_instructions (device_id, kind, instruction_id);
CREATE INDEX issued_instructions_age ON issued_instructions (issued_at);

CREATE TABLE device_instruction_log (
    device_id        uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    -- The last sequence of the device's log this server took.
    acked_seq        bigint NOT NULL DEFAULT 0 CHECK (acked_seq >= 0),
    -- Entries dated before this are not checked: the device claimed more
    -- than the server recorded, so the rows that would match may be gone.
    not_checked_before timestamptz,
    ahead_at         timestamptz,
    ahead_claimed    bigint,
    ahead_recorded   bigint,
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE device_instruction_flags (
    id             bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id      uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    seq            bigint NOT NULL CHECK (seq >= 1),
    kind           text NOT NULL CHECK (length(kind) BETWEEN 1 AND 16),
    instruction_id text NOT NULL CHECK (length(instruction_id) BETWEEN 1 AND 200),
    signer         text NOT NULL CHECK (length(signer) = 32),
    entry_at       timestamptz NOT NULL,
    flagged_at     timestamptz NOT NULL DEFAULT now(),
    -- Withdrawn when the device's claim of an unrecorded restore made its
    -- entries of that time not checked.
    withdrawn_at   timestamptz,
    UNIQUE (device_id, seq)
);

CREATE TABLE server_restores (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    restored_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    -- incident: `easyrmm-server incident restored`, which applies to every
    -- device. suspected: devices claimed more than the database recorded;
    -- it changes nothing for any other device until an incident record
    -- confirms it.
    source      text NOT NULL CHECK (source IN ('incident', 'suspected')),
    devices     uuid[] NOT NULL DEFAULT '{}',
    confirmed_at timestamptz
);

ALTER TABLE device_unknown_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_unknown_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY device_unknown_keys_read ON device_unknown_keys FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_unknown_keys_write ON device_unknown_keys FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON device_unknown_keys TO easyrmm_app;

ALTER TABLE issued_instructions ENABLE ROW LEVEL SECURITY;
ALTER TABLE issued_instructions FORCE ROW LEVEL SECURITY;
CREATE POLICY issued_instructions_all ON issued_instructions USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, DELETE ON issued_instructions TO easyrmm_app;

ALTER TABLE device_instruction_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_instruction_log FORCE ROW LEVEL SECURITY;
CREATE POLICY device_instruction_log_read ON device_instruction_log FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_instruction_log_write ON device_instruction_log FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON device_instruction_log TO easyrmm_app;

ALTER TABLE device_instruction_flags ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_instruction_flags FORCE ROW LEVEL SECURITY;
CREATE POLICY device_instruction_flags_read ON device_instruction_flags FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY device_instruction_flags_write ON device_instruction_flags FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON device_instruction_flags TO easyrmm_app;

ALTER TABLE server_restores ENABLE ROW LEVEL SECURITY;
ALTER TABLE server_restores FORCE ROW LEVEL SECURITY;
CREATE POLICY server_restores_all ON server_restores USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE ON server_restores TO easyrmm_app;

-- +goose Down
DROP TABLE server_restores;
DROP TABLE device_instruction_flags;
DROP TABLE device_instruction_log;
DROP TABLE issued_instructions;
DROP TABLE device_unknown_keys;
ALTER TABLE retired_devices
    DROP COLUMN job_key_given_generation,
    DROP COLUMN job_key_cutover_at,
    DROP COLUMN job_key_cutover_generation,
    DROP COLUMN job_keys_first_reported_at,
    DROP COLUMN job_keys_report_sha,
    DROP COLUMN job_keys_report_at,
    DROP COLUMN job_keys_report;
ALTER TABLE devices
    DROP COLUMN agent_authorities_at,
    DROP COLUMN agent_authorities,
    DROP COLUMN job_key_given_generation,
    DROP COLUMN job_key_cutover_at,
    DROP COLUMN job_key_cutover_generation,
    DROP COLUMN job_keys_first_reported_at,
    DROP COLUMN job_keys_report_sha,
    DROP COLUMN job_keys_report_at,
    DROP COLUMN job_keys_report;
