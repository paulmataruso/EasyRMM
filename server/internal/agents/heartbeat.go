package agents

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agentsettings"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/jobkeys"
)

// Heartbeat records that a device's agent is alive, refreshes its facts and
// links its MeshAgent when the agent reports one.
func (s *Service) Heartbeat(ctx context.Context, d *Device, ip netip.Addr, req agentproto.HeartbeatRequest) (*agentproto.HeartbeatResponse, error) {
	f, err := cleanFacts(req.Facts)
	if err != nil {
		return nil, apperr.Invalid("facts", err.Error())
	}
	var meshState []byte
	if req.MeshAgent != nil {
		meshState = s.meshState(ctx, d.SiteID, *req.MeshAgent)
	}
	linked := false
	var (
		update    *agentproto.SignedUpdate
		uninstall *agentproto.SignedUninstall
		handover  *agentproto.SignedKeyStatement
		cutover   *agentproto.SignedKeyStatement
		settings  *agentproto.SignedSettings
	)
	// What the agent may do about Defender, and what it reported of it
	// (ADR-0070); a bad report is refused before anything is stored.
	allowed := s.defenderAllowed(d.OrganizationID)
	report, err := checkDefenderReport(req)
	if err != nil {
		return nil, err
	}
	var (
		jobKey   jobkeys.Key
		keyAck   uint64
		keyTaken bool
		before   string
		// wasUninstalled: the device was marked Uninstalled before this
		// heartbeat (ADR-0053).
		wasUninstalled bool
		// installer is the package kind the agent reported (ADR-0056); a
		// value that is not one is ignored.
		installer = validInstaller(req.Installer)
		interval  = int(HeartbeatInterval.Seconds())
		rescan    bool
		logOn     bool
		logAck    *agentproto.DefenderLogAck
		logBatch  = req.DefenderLog
	)
	if logBatch != nil && logBatch.Check() != nil {
		logBatch = nil
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_ = tx.QueryRow(ctx, `SELECT coalesce(agent_version, ''), agent_uninstalled_at IS NOT NULL FROM devices WHERE id = $1`, d.ID).Scan(&before, &wasUninstalled)
		// The interval operators set for this device (ADR-0058). A failed
		// read never fails the heartbeat: the agent keeps today's minute.
		if n, err := agentsettings.EffectiveHeartbeat(ctx, tx, d.OrganizationID, d.SiteID, d.ID); err != nil {
			s.log.Error("agents: reading the heartbeat interval failed", "error", err, "device_id", d.ID)
		} else {
			interval = n
		}
		// The name follows the hostname until someone renames the device.
		// Online lasts three of the interval after this heartbeat; the
		// database works that out (easyrmm_device_online_until).
		tag, err := tx.Exec(ctx, `UPDATE devices SET
				name = CASE WHEN name = hostname THEN $2 ELSE name END,
				hostname = $2, os_description = $3, platform = $4, agent_version = $5, agent_arch = $6,
				agent_sha256 = NULLIF($7, ''), agent_last_seen_at = now(), agent_role = coalesce(NULLIF($9, ''), agent_role),
				agent_heartbeat_seconds = CASE
					WHEN $11::int > 0 THEN $11::int
					WHEN NOT $12::bool AND EXISTS (SELECT 1 FROM agent_device_state s
						WHERE s.device_id = devices.id AND s.capabilities IS NOT NULL AND s.capabilities_build = $13) THEN agent_heartbeat_seconds
					ELSE $10::int END,
				meshagent_state = coalesce($8::jsonb, meshagent_state),
				meshagent_state_at = CASE WHEN $8::jsonb IS NULL THEN meshagent_state_at ELSE now() END,
				installer = coalesce(NULLIF($14, ''), installer),
				ran_server_build_at = CASE WHEN $15::bool THEN coalesce(ran_server_build_at, now()) ELSE ran_server_build_at END,
				agent_uninstalled_at = NULL, agent_uninstalled_installer = NULL
			WHERE id = $1 AND agent_public_key IS NOT NULL`,
			d.ID, f.hostname, f.os, f.platform, f.version, f.arch, f.sha256, meshState, f.role, interval,
			reportedInterval(req), req.Capabilities != nil, buildOf(f), installer, s.runsServedBuild(d, f))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrUnknownDevice
		}
		if wasUninstalled {
			// An agent restored from a backup checked in: the notice is moot
			// (ADR-0053).
			if _, err := tx.Exec(ctx, `UPDATE notices SET resolved_at = now()
				WHERE kind = $1 AND subject = $2 AND resolved_at IS NULL`, NoticeAgentUninstalled, d.ID.String()); err != nil {
				return err
			}
		}
		if allowed {
			if err := s.storeDefender(ctx, tx, d, f.hostname, ip, report); err != nil {
				return err
			}
			logOn, logAck = s.storeDefenderLog(ctx, tx, d, logBatch)
		}
		// Like the update, the roles are an extra: a failure to store them
		// never fails the heartbeat.
		if s.roles != nil {
			rp, err := tx.Begin(ctx)
			if err != nil {
				return err
			}
			if rescan, err = s.roles.StoreRoles(ctx, rp, d.ID, d.OrganizationID, f.roles); err != nil {
				s.log.Error("agents: storing the roles failed", "error", err, "device_id", d.ID)
				rescan = false
				if err := rp.Rollback(ctx); err != nil {
					return err
				}
			} else if err := rp.Commit(ctx); err != nil {
				return err
			}
		}
		if f.meshNode != "" && f.meshNode != d.MeshNodeID {
			if linked, err = s.link(ctx, tx, d, f, ip); err != nil {
				return err
			}
		}
		// What the device trusts (ADR-0057), stored before anything is signed
		// for it, and the key its answer is signed with.
		if s.keys != nil {
			var err error
			if jobKey, keyAck, keyTaken, err = s.followKeys(ctx, tx, d, f.hostname, f.sha256, ip, req); err != nil {
				return err
			}
		}
		// A device being removed gets nothing but its uninstall
		// instruction (ADR-0050).
		if uninstall, err = s.uninstallFor(ctx, tx, d); err != nil || uninstall != nil {
			return err
		}
		settings = s.followSettings(ctx, tx, d, f, req)
		// The update is an extra: when settling it fails, the heartbeat
		// still counts.
		sp, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		if update, err = s.planUpdate(ctx, sp, d, f, req.Update, ip); err != nil {
			s.log.Error("agents: settling the agent update failed", "error", err, "device_id", d.ID)
			update = nil
			return sp.Rollback(ctx)
		}
		if err := sp.Commit(ctx); err != nil {
			return err
		}
		handover, cutover = s.offerKeys(ctx, tx, d, update)
		return nil
	})
	if errors.Is(err, ErrUnknownDevice) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("agents: heartbeat: %w", err)
	}
	if linked && s.mesh != nil {
		s.mesh.Linked()
	}
	if s.version != nil && f.version != "" && f.version != before {
		// A build the list may not hold yet (ADR-0070).
		s.version(f.version)
	}
	available, err := s.meshAvailable(ctx, d.SiteID)
	if err != nil {
		s.log.Warn("agents: checking remote access failed", "error", err, "device_id", d.ID)
	}
	return &agentproto.HeartbeatResponse{
		Protocol:         agentproto.Protocol,
		HeartbeatSeconds: interval,
		MeshAgent:        agentproto.MeshAgentInfo{Available: available, SettingsSHA256: s.pendingSettings(ctx, d, f, available)},
		JobKey:           encodedOrEmpty(jobKey),
		JobKeyGeneration: jobKey.Generation,
		Features:         s.keyFeatures(),
		InstructionAck:   ackFor(keyTaken, keyAck),
		Update:           update,
		Settings:         settings,
		Uninstall:        uninstall,
		KeyHandover:      handover,
		KeyCutover:       cutover,
		Defender:         &agentproto.DefenderPolicy{Enabled: allowed, Events: logOn, EventsAck: logAck},
		RescanRoles:      rescan,
	}, nil
}

// validInstaller returns the package kind an agent reported as its installer,
// or "" for none or for a value that is not one (ADR-0056).
func validInstaller(s string) string {
	if s == "" || !agentproto.ValidInstaller(s) {
		return ""
	}
	return s
}

// runsServedBuild says whether the device runs the build the server serves
// for it now, which records that it has run the server's build once
// (ADR-0056). A build the server withholds (signed builds only, none signed)
// has no hash and counts for nothing.
func (s *Service) runsServedBuild(d *Device, f facts) bool {
	if f.sha256 == "" {
		return false
	}
	b := s.BuildsFor(d.OrganizationID)
	if b == nil {
		return false
	}
	served, ok := b.For(f.platform, f.arch)
	return ok && served.SHA256 != "" && served.SHA256 == f.sha256
}

// buildOf names the build that sent a heartbeat for the settings report: the
// SHA-256 of its executable, or its version for an agent that sends none
// (ADR-0058).
func buildOf(f facts) string {
	if f.sha256 != "" {
		return f.sha256
	}
	return "version:" + f.version
}

// reportedInterval is the interval the agent says it uses, 0 when the
// heartbeat has no report or the value is outside what the database keeps.
func reportedInterval(req agentproto.HeartbeatRequest) int {
	if req.Capabilities == nil || req.HeartbeatSeconds < agentproto.MinHeartbeatSeconds || req.HeartbeatSeconds > agentproto.MaxHeartbeatSeconds {
		return 0
	}
	return req.HeartbeatSeconds
}

// followSettings records the agent's report for signed settings and returns
// the document the answer carries (ADR-0058). It is an extra like the update:
// a failure to settle it is logged and never fails the heartbeat, and the
// device is given the document with its next one.
func (s *Service) followSettings(ctx context.Context, tx pgx.Tx, d *Device, f facts, req agentproto.HeartbeatRequest) *agentproto.SignedSettings {
	if s.keys == nil {
		return nil
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return nil
	}
	sign := func(ctx context.Context, tx pgx.Tx, device uuid.UUID, id string) (ed25519.PrivateKey, error) {
		k, _, err := s.keys.Issue(ctx, tx, device, agentproto.InstructionSettings, id)
		return k, err
	}
	doc, err := agentsettings.Follow(ctx, sp, s.log, sign, agentsettings.Beat{
		Device: agentsettings.DeviceRef{ID: d.ID, Org: d.OrganizationID, Site: d.SiteID}, Build: buildOf(f),
		Capabilities: req.Capabilities, Report: req.Settings, HeartbeatSeconds: req.HeartbeatSeconds,
		SignedAt: signedAt(ctx, s.now()), Now: s.now(),
	})
	if err != nil {
		s.log.Error("agents: settling the agent's settings failed", "error", err, "device_id", d.ID)
		_ = sp.Rollback(ctx)
		return nil
	}
	if err := sp.Commit(ctx); err != nil {
		return nil
	}
	return doc
}

// movingFrom reports whether d was moved to its site from the site whose
// device group a node is in: the node is d's, on its way to the new group
// (ADR-0069).
func (s *Service) movingFrom(ctx context.Context, tx pgx.Tx, d *Device, site uuid.UUID) bool {
	var from *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT mesh_from_site_id FROM devices WHERE id = $1`, d.ID).Scan(&from); err != nil {
		return false
	}
	return from != nil && *from == site
}

// pendingSettings is the hash of the MeshAgent settings an agent must apply
// after its device moved to another site, or "" when none are pending. The
// agent reports the hash it applied; the instruction ends when they agree.
func (s *Service) pendingSettings(ctx context.Context, d *Device, f facts, available bool) string {
	if !available {
		return ""
	}
	var pending bool
	if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT mesh_settings_pending FROM devices WHERE id = $1`, d.ID).Scan(&pending)
	}); err != nil || !pending {
		return ""
	}
	b, err := s.MeshAgentSettings(ctx, d)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	want := hex.EncodeToString(sum[:])
	if f.meshSettings != want {
		return want
	}
	if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE devices SET mesh_settings_pending = false WHERE id = $1`, d.ID)
		return err
	}); err != nil {
		s.log.Warn("agents: settling the MeshAgent settings failed", "error", err, "device_id", d.ID)
	}
	return ""
}

// link attaches the MeshCentral node the agent reported to its device.
//
// The node id is not a secret, so a report is only believed within the
// device's own site: a device discovered there under that node is merged
// into the enrolled one, and an enrolled device holding the node (the same
// machine enrolled again) gives it up. A node already known in another site
// is left alone; MeshCentral's device sync also unlinks an enrolled device
// whose node turns out to belong to another site's group.
func (s *Service) link(ctx context.Context, tx pgx.Tx, d *Device, f facts, ip netip.Addr) (bool, error) {
	var (
		otherID   uuid.UUID
		otherSite uuid.UUID
		otherName string
		enrolled  bool
		agentType *int
		online    bool
		lastSeen  *time.Time
	)
	err := tx.QueryRow(ctx, `SELECT id, site_id, name, agent_public_key IS NOT NULL, mesh_agent_type, remote_online, last_seen_at
		FROM devices WHERE mesh_node_id = $1 FOR UPDATE`, f.meshNode).
		Scan(&otherID, &otherSite, &otherName, &enrolled, &agentType, &online, &lastSeen)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// MeshCentral has not reported the node yet; its next device sync
		// confirms or undoes the link.
		_, err = tx.Exec(ctx, `UPDATE devices SET mesh_node_id = $2, mesh_agent_type = NULL, remote_online = false WHERE id = $1`, d.ID, f.meshNode)
		if err == nil {
			err = keepNode(ctx, tx, d, f.meshNode)
		}
		return err == nil, err
	case err != nil:
		return false, err
	case otherSite != d.SiteID && !s.movingFrom(ctx, tx, d, otherSite):
		s.log.Warn("agents: a device reported a MeshAgent node of another site; not linked",
			"device_id", d.ID, "node_device_id", otherID)
		return false, nil
	}
	details := map[string]any{"device": f.hostname}
	if enrolled {
		_, err = tx.Exec(ctx, `UPDATE devices SET mesh_node_id = NULL, mesh_agent_type = NULL, remote_online = false WHERE id = $1`, otherID)
		details["previousDevice"], details["previousDeviceId"] = otherName, otherID.String()
	} else {
		// Sessions started on the discovered device now belong to this one.
		if _, err = tx.Exec(ctx, `UPDATE remote_grants SET device_id = $2 WHERE device_id = $1`, otherID, d.ID); err == nil {
			// The journal reads the reason from this setting, so that the
			// alerts the deletion takes read as merged, not removed.
			if _, err = tx.Exec(ctx, `SELECT set_config('easyrmm.alert_delete_reason', 'merged', true)`); err == nil {
				_, err = tx.Exec(ctx, `DELETE FROM devices WHERE id = $1`, otherID)
			}
			if err == nil {
				_, err = tx.Exec(ctx, `SELECT set_config('easyrmm.alert_delete_reason', '', true)`)
			}
		}
		details["mergedDevice"], details["mergedDeviceId"] = otherName, otherID.String()
	}
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `UPDATE devices SET mesh_node_id = $2, mesh_agent_type = $3, remote_online = $4,
			last_seen_at = greatest(last_seen_at, $5) WHERE id = $1`,
		d.ID, f.meshNode, agentType, online, lastSeen); err != nil {
		return false, err
	}
	if err := keepNode(ctx, tx, d, f.meshNode); err != nil {
		return false, err
	}
	err = s.audit.Write(ctx, tx, audit.Event{
		Actor:  audit.Actor{Type: audit.ActorAgent, ID: d.ID, Label: f.hostname, SourceIP: ip},
		Action: "device.remote_link", Outcome: audit.Success,
		OrganizationID: d.OrganizationID, SiteID: d.SiteID, DeviceID: d.ID, TargetType: "device", TargetID: d.ID.String(),
		Details: details,
	})
	return err == nil, err
}

// keepNode lets a device linked to a MeshAgent node keep it when the node
// belonged to a device removed from the same site (ADR-0050): the computer
// was enrolled again, so its MeshAgent is not to be uninstalled.
func keepNode(ctx context.Context, tx pgx.Tx, d *Device, node string) error {
	_, err := tx.Exec(ctx, `UPDATE retired_devices SET mesh_node_id = NULL WHERE mesh_node_id = $1 AND site_id = $2`, node, d.SiteID)
	return err
}

type signedAtKey struct{}

// WithSignedAt gives a request's context the time in its signature, on the
// agent's clock: a report of the keys an agent trusts is stored only when it
// is newer than the stored one (ADR-0057). Without it the server's clock is
// used.
func WithSignedAt(ctx context.Context, t time.Time) context.Context {
	return context.WithValue(ctx, signedAtKey{}, t)
}

func signedAt(ctx context.Context, fallback time.Time) time.Time {
	if t, ok := ctx.Value(signedAtKey{}).(time.Time); ok && !t.IsZero() {
		return t
	}
	return fallback
}

// followKeys is what a heartbeat does with the keys the agent trusts
// (ADR-0057), in the heartbeat's transaction: it stores the report, audits a
// statement the agent refused, takes the instruction log, and returns the key
// the answer and everything signed for the device after it use. The report,
// the refusal and the log are extras like the roles: a failure to store them
// never fails the heartbeat, and a log that could not be stored is not
// acknowledged. Choosing the key is not an extra.
func (s *Service) followKeys(ctx context.Context, tx pgx.Tx, d *Device, hostname, build string, ip netip.Addr, req agentproto.HeartbeatRequest) (key jobkeys.Key, ack uint64, taken bool, err error) {
	o := jobkeys.Observation{Device: d.ID, Org: d.OrganizationID, Site: d.SiteID, Label: hostname, IP: ip,
		Keys: req.JobKeys, Authorities: req.Authorities, SignedAt: signedAt(ctx, s.now()), Build: build}
	if len(o.Keys) > 0 || o.Authorities != nil || req.KeyRefused != nil || req.InstructionLog != nil {
		sp, err := tx.Begin(ctx)
		if err != nil {
			return jobkeys.Key{}, 0, false, err
		}
		var res jobkeys.LogResult
		err = s.keys.Observe(ctx, sp, o)
		if err == nil && req.KeyRefused != nil {
			err = s.keys.RefusedStatement(ctx, sp, o, *req.KeyRefused)
		}
		if err == nil && req.InstructionLog != nil {
			res, err = s.keys.AcceptLog(ctx, sp, jobkeys.LogDevice{ID: d.ID, Org: d.OrganizationID, Site: d.SiteID, Label: hostname}, *req.InstructionLog, s.now())
			ack, taken = res.Ack, err == nil
		}
		if err != nil {
			s.log.Error("agents: storing what the agent trusts failed", "error", err, "device_id", d.ID)
			ack, taken = 0, false
			if err := sp.Rollback(ctx); err != nil {
				return jobkeys.Key{}, 0, false, err
			}
		} else if err := sp.Commit(ctx); err != nil {
			return jobkeys.Key{}, 0, false, err
		}
	}
	c, err := s.keys.For(ctx, tx, d.ID)
	if err != nil {
		return jobkeys.Key{}, 0, false, err
	}
	return c.Key, ack, taken, nil
}

// ObservePoll stores the keys a job poll says the agent trusts, as a
// heartbeat's report is stored, before the poll claims anything.
func (s *Service) ObservePoll(ctx context.Context, d *Device, keys []agentproto.TrustedKey) {
	if s.keys == nil || len(keys) == 0 {
		return
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return s.keys.Observe(ctx, tx, jobkeys.Observation{Device: d.ID, Org: d.OrganizationID, Site: d.SiteID, Label: d.Hostname,
			Keys: keys, SignedAt: signedAt(ctx, s.now())})
	})
	if err != nil && ctx.Err() == nil {
		s.log.Error("agents: storing what the agent trusts from its poll failed", "error", err, "device_id", d.ID)
	}
}

// keyFeatures lists what the server offers about the job keys: it takes the
// instruction log (ADR-0057).
func (s *Service) keyFeatures() []string {
	if s.keys != nil && s.keys.Logs() {
		return []string{agentproto.FeatureInstructionLog}
	}
	return nil
}

// ackFor is the answer's acknowledgment: none unless the log was taken.
func ackFor(taken bool, ack uint64) uint64 {
	if taken {
		return ack
	}
	return 0
}

// offerKeys decides the statement the answer carries to move the device
// between job keys (ADR-0057, "What the server offers each device"), after
// planUpdate in the same transaction, and never while an agent update is open
// for the device (one placed in this very answer included). It is an extra
// like the update: a failure to decide it never fails the heartbeat, and the
// device is offered it again with its next one. Organizations outside the dev
// scope are offered nothing.
func (s *Service) offerKeys(ctx context.Context, tx pgx.Tx, d *Device, update *agentproto.SignedUpdate) (handover, cutover *agentproto.SignedKeyStatement) {
	o, ok := s.keys.(jobkeys.Offerer)
	if !ok || update != nil || !devscope.Allowed(d.OrganizationID) {
		return nil, nil
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return nil, nil
	}
	var open bool
	if err := sp.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_updates WHERE device_id = $1 AND state = 'sent')`, d.ID).Scan(&open); err != nil || open {
		_ = sp.Rollback(ctx)
		return nil, nil
	}
	st, err := o.Offer(ctx, sp, d.ID)
	if err != nil {
		s.log.Error("agents: deciding a job key statement failed", "error", err, "device_id", d.ID)
		_ = sp.Rollback(ctx)
		return nil, nil
	}
	if err := sp.Commit(ctx); err != nil {
		return nil, nil
	}
	return st.Handover, st.Cutover
}
