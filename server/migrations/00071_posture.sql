-- Endpoint security posture (ADR-0082, slice P1). Posture is a view over what
-- hardening and patching already keep, so this adds no results of its own. The
-- one table is a copy of the patching engine's compliance word for each linked
-- device, with the time it was read, because the engine answers over HTTP and
-- the Devices list, the Security report and the alert evaluator must read it
-- with a query. It goes stale like any result (the organization's freshness
-- window), and a stale copy never counts as passing.

-- +goose Up
CREATE TABLE posture_patching (
    device_id  uuid PRIMARY KEY REFERENCES devices (id) ON DELETE CASCADE,
    -- EasyPatch's ComplianceStatus, as it said it.
    status     text NOT NULL CHECK (length(status) BETWEEN 1 AND 40),
    checked_at timestamptz NOT NULL
);

ALTER TABLE posture_patching ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture_patching FORCE ROW LEVEL SECURITY;
CREATE POLICY posture_patching_read ON posture_patching FOR SELECT
    USING (easyrmm_scope_all() OR EXISTS (SELECT 1 FROM devices d WHERE d.id = device_id));
CREATE POLICY posture_patching_write ON posture_patching FOR ALL
    USING (easyrmm_scope_all()) WITH CHECK (easyrmm_scope_all());
GRANT SELECT, INSERT, UPDATE, DELETE ON posture_patching TO easyrmm_app;

-- The two compliance alerts (ADR-0078 section 7, built with ADR-0082) belong to
-- no policy, as Repair failed does. subject is the control for a failed fix
-- and 'scan' for an out-of-date scan; at most one is unresolved for each.
CREATE UNIQUE INDEX alerts_compliance_key ON alerts (device_id, kind, subject)
    WHERE kind IN ('compliance_fix_failed', 'compliance_scan_stale') AND status <> 'resolved';

-- +goose Down
SELECT set_config('easyrmm.scope_all', 'on', true);
DELETE FROM alerts WHERE kind IN ('compliance_fix_failed', 'compliance_scan_stale');
DROP INDEX alerts_compliance_key;
DROP TABLE posture_patching;
