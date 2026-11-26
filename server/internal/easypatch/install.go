package easypatch

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Installing the EasyPatch agent (ADR-0031): someone asks, or an
// organization installs automatically; the device's agent is sent a signed
// instruction with its next heartbeat, installs, and reports how it went.

// Install states of a device.
const (
	InstallWaiting   = "waiting"
	InstallSent      = "sent"
	InstallSucceeded = "succeeded"
	InstallFailed    = "failed"
)

const (
	// installValidFor is how long an agent may act on an instruction.
	installValidFor = 15 * time.Minute
	// installTimeout is how long an agent has to report an install.
	installTimeout = 30 * time.Minute
	// installLost is how soon an attempt the agent does not mention in its
	// heartbeats counts as lost: it never got the instruction, or restarted.
	installLost = 3 * time.Minute
	// autoAttempts and autoRetry bound automatic installs.
	autoAttempts = 3
	autoRetry    = time.Hour
)

// Notes on a waiting install.
const noteOldAgent = "This device's EasyRMM agent is too old to install the EasyPatch agent. It will once it updates."

// AgentInstall is a device's EasyPatch agent install, as the console shows it.
type AgentInstall struct {
	State       string     `json:"state"`
	Automatic   bool       `json:"automatic"`
	RequestedBy string     `json:"requestedBy,omitempty"`
	RequestedAt time.Time  `json:"requestedAt"`
	Attempts    int        `json:"attempts"`
	SentAt      *time.Time `json:"sentAt,omitempty"`
	FinishedAt  *time.Time `json:"finishedAt,omitempty"`
	Error       string     `json:"error,omitempty"`
	// Note says why a waiting install has not been sent.
	Note string `json:"note,omitempty"`
}

// installColumns read an install joined as x, with its requester as xu.
const installColumns = `x.state, x.automatic, xu.email, x.requested_at, x.attempts, x.sent_at, x.finished_at, x.error, x.note`

const installJoin = ` LEFT JOIN easypatch_installs x ON x.device_id = d.id LEFT JOIN users xu ON xu.id = x.requested_by`

// installScan holds the nullable columns of installColumns.
type installScan struct {
	state, by, errText, note *string
	automatic                *bool
	requestedAt              *time.Time
	attempts                 *int
	sentAt, finishedAt       *time.Time
}

func (s *installScan) dest() []any {
	return []any{&s.state, &s.automatic, &s.by, &s.requestedAt, &s.attempts, &s.sentAt, &s.finishedAt, &s.errText, &s.note}
}

func (s *installScan) view() *AgentInstall {
	if s.state == nil {
		return nil
	}
	v := &AgentInstall{State: *s.state, Automatic: *s.automatic, RequestedAt: *s.requestedAt, Attempts: *s.attempts,
		SentAt: s.sentAt, FinishedAt: s.finishedAt, Error: *s.errText, Note: *s.note}
	if s.by != nil {
		v.RequestedBy = *s.by
	}
	return v
}

// SetSigner gives the service the server's job key, which signs install
// instructions as it signs jobs and updates. Without it nothing is sent.
func (s *Service) SetSigner(key ed25519.PrivateKey) { s.signer = key }

// ---------------------------------------------------------------- eligibility

// installTarget is what deciding about a device's install needs.
type installTarget struct {
	id, organizationID, siteID uuid.UUID
	name, siteName             string
	platform, arch             string
	enrolled, inventoried      bool
	report                     *agentproto.EasyPatchAgent
	easyPatchOrg               *uuid.UUID
	autoInstall                bool
	// easyPatchSite is the engine site linked to the device's (ADR-0040).
	easyPatchSite *uuid.UUID
	// optedOut: patching was stopped for the device; removing: EasyRMM is
	// removing its EasyPatch agent.
	optedOut, removing bool
}

const targetSelect = `SELECT d.id, d.organization_id, d.site_id, d.name, s.name, d.platform, coalesce(d.agent_arch, ''), d.agent_public_key IS NOT NULL,
		i.device_id IS NOT NULL, i.data->'easyPatch', l.easypatch_id, coalesce(l.auto_install, false), ls.easypatch_id,
		EXISTS (SELECT 1 FROM easypatch_opt_outs o WHERE o.device_id = d.id), EXISTS (SELECT 1 FROM easypatch_removals r WHERE r.device_id = d.id)
	FROM devices d JOIN sites s ON s.id = d.site_id
	LEFT JOIN device_inventory i ON i.device_id = d.id
	LEFT JOIN easypatch_organizations l ON l.organization_id = d.organization_id
	LEFT JOIN easypatch_sites ls ON ls.site_id = d.site_id
	WHERE d.id = $1`

func loadTarget(ctx context.Context, tx pgx.Tx, id uuid.UUID) (installTarget, error) {
	var t installTarget
	var report []byte
	err := tx.QueryRow(ctx, targetSelect, id).Scan(&t.id, &t.organizationID, &t.siteID, &t.name, &t.siteName, &t.platform, &t.arch,
		&t.enrolled, &t.inventoried, &report, &t.easyPatchOrg, &t.autoInstall, &t.easyPatchSite, &t.optedOut, &t.removing)
	if err != nil {
		return t, err
	}
	if len(report) > 0 && string(report) != "null" {
		var rep agentproto.EasyPatchAgent
		if json.Unmarshal(report, &rep) == nil {
			t.report = &rep
		}
	}
	return t, nil
}

// formats are the EasyPatch package formats a platform installs.
func formats(platform string) []string {
	switch platform {
	case "windows":
		return []string{agentproto.EasyPatchMSI}
	case "linux":
		return []string{agentproto.EasyPatchDeb, agentproto.EasyPatchRPM}
	}
	return nil
}

// notEnrolled is the EasyPatch agent's status before it enrolls.
const notEnrolled = "NotEnrolled"

// ineligible says why the EasyPatch agent cannot be installed on a device,
// "" when it can.
func (t *installTarget) ineligible() string {
	switch {
	case t.optedOut:
		return "Patching is stopped for this device. Allow patching again first."
	case t.removing:
		return "EasyRMM is removing this device's EasyPatch agent. Try again once it is gone."
	case t.easyPatchOrg == nil:
		return "This device's organization has no patching organization yet: EasyRMM makes it on its next pass. Try again in a minute."
	case !t.enrolled:
		return "This device has no EasyRMM agent to install the EasyPatch agent with."
	case formats(t.platform) == nil:
		return "The EasyPatch agent is for Windows and Linux only."
	case agentproto.EasyPatchArch(t.arch) == "":
		return fmt.Sprintf("There is no EasyPatch agent for %s processors.", t.arch)
	case !t.inventoried:
		return "This device's agent has not reported its inventory yet, so EasyRMM cannot tell whether it has an EasyPatch agent. Try again in a few minutes."
	case t.report != nil && t.report.Status != notEnrolled:
		status := t.report.Status
		if status == "" {
			status = "status unknown"
		}
		return fmt.Sprintf("This device already has an EasyPatch agent (%s); EasyRMM leaves it alone.", status)
	}
	return ""
}

// ---------------------------------------------------------------- requests

// InstallAgent has devices install the EasyPatch agent at their next
// heartbeat.
func (s *Service) InstallAgent(ctx context.Context, c access.Caller, in ActionInput) (ActionResult, error) {
	if len(in.UpdateIDs) > 0 || in.ScheduledAt != nil {
		return ActionResult{}, apperr.Invalid("deviceIds", "Installing the EasyPatch agent takes devices only.")
	}
	if len(in.DeviceIDs) == 0 || len(in.DeviceIDs) > MaxBulk {
		return ActionResult{}, apperr.Invalid("deviceIds", fmt.Sprintf("Choose from 1 to %d devices.", MaxBulk))
	}
	if _, _, err := s.operable(ctx); err != nil {
		return ActionResult{}, err
	}
	if s.signer == nil {
		return ActionResult{}, apperr.Unavailable("easypatch_no_signer", "This server cannot sign instructions for agents.")
	}
	// Every device is checked before any is changed: a request with one the
	// caller may not manage changes nothing.
	seen := map[uuid.UUID]bool{}
	var devices []deviceRow
	for _, id := range in.DeviceIDs {
		if seen[id] {
			continue
		}
		seen[id] = true
		d, err := s.device(ctx, c, id, rbac.PermPatchManage)
		if err != nil {
			return ActionResult{}, err
		}
		devices = append(devices, d)
	}
	var by *uuid.UUID
	if c.Actor.Type == audit.ActorUser && c.Actor.ID != uuid.Nil {
		by = &c.Actor.ID
	}
	res := ActionResult{Results: []ActionItem{}}
	for _, d := range devices {
		id := d.id
		item := ActionItem{DeviceID: d.id, DeviceName: d.name}
		err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
			t, err := loadTarget(ctx, tx, id)
			if err != nil {
				return err
			}
			if why := t.ineligible(); why != "" {
				item.Message = why
				return nil
			}
			var state string
			err = tx.QueryRow(ctx, `SELECT state FROM easypatch_installs WHERE device_id = $1 FOR UPDATE`, id).Scan(&state)
			switch {
			case errors.Is(err, pgx.ErrNoRows):
			case err != nil:
				return err
			case state == InstallSent:
				item.Message = "The device is installing the EasyPatch agent now."
				return nil
			case state == InstallWaiting:
				item.OK, item.Message = true, "Already waiting for the device."
				return nil
			}
			if _, err := tx.Exec(ctx, `INSERT INTO easypatch_installs (device_id, state, automatic, requested_by, requested_at)
				VALUES ($1, 'waiting', false, $2, now())
				ON CONFLICT (device_id) DO UPDATE SET state = 'waiting', automatic = false, requested_by = $2, requested_at = now(),
					attempts = 0, attempt_id = NULL, token_id = NULL, sent_at = NULL, finished_at = NULL, error = '', note = ''`,
				id, by); err != nil {
				return err
			}
			item.OK = true
			return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "patch.agent_install", OrganizationID: t.organizationID,
				SiteID: t.siteID, DeviceID: id, TargetType: "device", TargetID: id.String(), Outcome: audit.Success,
				Details: map[string]any{"device": t.name}})
		})
		if err != nil {
			return ActionResult{}, err
		}
		res.add(item)
	}
	s.fleet.clear()
	return res, nil
}

// SetAutoInstall turns automatic installs on or off for a linked
// organization.
func (s *Service) SetAutoInstall(ctx context.Context, actor audit.Actor, organizationID uuid.UUID, on bool) error {
	if on {
		if _, _, err := s.operable(ctx); err != nil {
			return err
		}
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var name string
		var was bool
		err := tx.QueryRow(ctx, `SELECT o.name, l.auto_install FROM easypatch_organizations l JOIN organizations o ON o.id = l.organization_id
			WHERE l.organization_id = $1 FOR UPDATE OF l`, organizationID).Scan(&name, &was)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		} else if err != nil {
			return err
		}
		if was == on {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE easypatch_organizations SET auto_install = $2 WHERE organization_id = $1`, organizationID, on); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "easypatch.organization_update", OrganizationID: organizationID,
			TargetType: "organization", TargetID: organizationID.String(), Outcome: audit.Success,
			Details: map[string]any{"organization": name, "autoInstall": on}})
	})
}

// ---------------------------------------------------------------- heartbeats

// AgentHeartbeat settles a device's install with what its agent reports
// (nil from agents that cannot install) and returns the instruction to send,
// nil for none. Failures are logged: the heartbeat counts regardless.
func (s *Service) AgentHeartbeat(ctx context.Context, deviceID uuid.UUID, st *agentproto.EasyPatchInstallStatus) *agentproto.SignedEasyPatchInstall {
	out, err := s.agentHeartbeat(ctx, deviceID, st)
	if err != nil {
		s.log.Error("easypatch: settling the agent install failed", "error", err, "device_id", deviceID)
		return nil
	}
	return out
}

func (s *Service) agentHeartbeat(ctx context.Context, deviceID uuid.UUID, st *agentproto.EasyPatchInstallStatus) (*agentproto.SignedEasyPatchInstall, error) {
	var (
		state, note string
		attempt     *uuid.UUID
		sentAt      *time.Time
	)
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT state, attempt_id, sent_at, note FROM easypatch_installs WHERE device_id = $1`, deviceID).
			Scan(&state, &attempt, &sentAt, &note)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	switch state {
	case InstallSent:
		if st == nil || attempt == nil {
			return nil, nil
		}
		id := attempt.String()
		switch {
		case st.Last != nil && st.Last.ID == id:
			msg := ""
			if !st.Last.OK {
				msg = cut(strings.TrimSpace(st.Last.Error), agentproto.MaxEasyPatchError)
				if msg == "" {
					msg = "The agent did not say why."
				}
			}
			return nil, s.finish(ctx, deviceID, *attempt, msg)
		case st.Busy == id:
		case sentAt != nil && s.now().Sub(*sentAt) >= installLost:
			return nil, s.finish(ctx, deviceID, *attempt, "The device's agent did not get the instruction, or restarted while installing. Try again.")
		}
		return nil, nil
	case InstallWaiting:
		if st == nil {
			if note != noteOldAgent {
				err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, `UPDATE easypatch_installs SET note = $2 WHERE device_id = $1 AND state = 'waiting'`, deviceID, noteOldAgent)
					return err
				})
				return nil, err
			}
			return nil, nil
		}
		if st.Busy != "" || s.signer == nil {
			return nil, nil
		}
		return s.send(ctx, deviceID)
	}
	return nil, nil
}

// send claims a waiting install and builds its instruction; when that
// fails, the attempt fails with the reason.
func (s *Service) send(ctx context.Context, deviceID uuid.UUID) (*agentproto.SignedEasyPatchInstall, error) {
	attempt := uuid.New()
	var requester *string
	claimed := false
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `UPDATE easypatch_installs x SET state = 'sent', attempt_id = $2, sent_at = now(), attempts = attempts + 1, note = ''
			WHERE x.device_id = $1 AND x.state = 'waiting'
			RETURNING (SELECT email FROM users WHERE id = x.requested_by)`, deviceID, attempt).Scan(&requester)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		claimed = err == nil
		return err
	})
	if err != nil || !claimed {
		return nil, err
	}
	onBehalfOf := ""
	if requester != nil {
		onBehalfOf = *requester
	}
	signed, tokenID, why, err := s.instruction(ctx, deviceID, attempt, onBehalfOf)
	if err != nil {
		// Our own failure, not the device's: the attempt fails with a
		// generic reason and the details go to the log.
		s.log.Error("easypatch: preparing the agent install failed", "error", err, "device_id", deviceID)
		why = "EasyRMM could not prepare the install. The server log has the details."
	}
	if why != "" {
		if tokenID != nil {
			s.revoke(ctx, *tokenID)
		}
		return nil, s.finish(ctx, deviceID, attempt, why)
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE easypatch_installs SET token_id = $3 WHERE device_id = $1 AND attempt_id = $2`, deviceID, attempt, *tokenID)
		return err
	})
	if err != nil {
		s.revoke(ctx, *tokenID)
		return nil, err
	}
	s.fleet.clear()
	return signed, nil
}

// instruction builds and signs an install for a device. why says what
// stops it, for the device's install state.
func (s *Service) instruction(ctx context.Context, deviceID, attempt uuid.UUID, onBehalfOf string) (_ *agentproto.SignedEasyPatchInstall,
	tokenID *uuid.UUID, why string, err error) {
	r, cl, err := s.operable(ctx)
	if err != nil {
		var ae *apperr.Error
		if errors.As(err, &ae) {
			return nil, nil, ae.Message, nil
		}
		return nil, nil, "", err
	}
	var t installTarget
	err = s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) (err error) {
		t, err = loadTarget(ctx, tx, deviceID)
		return err
	})
	if err != nil {
		return nil, nil, "", err
	}
	if why := t.ineligible(); why != "" {
		return nil, nil, why, nil
	}
	// Agents enroll with the engine's public address (EasyRMM's own), never
	// its loopback one.
	server := strings.TrimRight(r.publicURL, "/")
	if server == "" {
		return nil, nil, "The patching engine has no public address for agents to enroll with. Check that it runs with EASYRMM_PUBLIC_URL.", nil
	}
	pkgs, err := cl.AgentPackages(ctx)
	if err != nil {
		s.noteError(err)
		return nil, nil, "The patching engine could not list its agent packages: " + message(epError(err)), nil
	}
	chosen := choosePackages(pkgs, server, t.platform, agentproto.EasyPatchArch(t.arch))
	if len(chosen) == 0 {
		return nil, nil, fmt.Sprintf("The patching engine has no agent package for %s %s. Its packages are listed under Settings → Patching → Agent packages.",
			platformName(t.platform), agentproto.EasyPatchArch(t.arch)), nil
	}
	site := t.easyPatchSite
	if site == nil {
		sites, err := cl.Sites(ctx, *t.easyPatchOrg)
		if err != nil {
			s.noteError(err)
			return nil, nil, "The patching engine could not list the organization's sites: " + message(epError(err)), nil
		}
		for _, x := range sites {
			if strings.EqualFold(strings.TrimSpace(x.Name), strings.TrimSpace(t.siteName)) {
				site = &x.ID
				break
			}
		}
	}
	token, err := cl.CreateEnrollmentToken(ctx, *t.easyPatchOrg, site, cut("EasyRMM install on "+t.name, 200), onBehalfOf)
	if err != nil {
		s.noteError(err)
		return nil, nil, "The patching engine did not create an enrollment token: " + message(epError(err)), nil
	}
	now := s.now()
	p := agentproto.EasyPatchInstallPayload{
		V: agentproto.EasyPatchInstallVersion, ID: attempt.String(), DeviceID: deviceID.String(),
		ServerURL: server, CACert: caForAgent(r.caCert), Packages: chosen, Token: token.Secret,
		IssuedAt: now.UTC(), ExpiresAt: now.Add(installValidFor).UTC(),
	}
	signed, err := agentproto.SignEasyPatchInstall(s.signer, p)
	if err != nil {
		return nil, &token.ID, "", err
	}
	// The agent checks the instruction as strictly; refuse here what it
	// would refuse there, with a reason someone can act on.
	pub, _ := s.signer.Public().(ed25519.PublicKey)
	if _, err := agentproto.VerifyEasyPatchInstall(pub, signed, deviceID.String(), now); err != nil {
		return nil, &token.ID, "The patching engine's address, packages or enrollment token are not in a form the agent accepts: " +
			strings.TrimPrefix(err.Error(), "agentproto: ") + ". Check the patching engine's public address (https) and its agent packages.", nil
	}
	return &signed, &token.ID, "", nil
}

func platformName(p string) string {
	switch p {
	case "windows":
		return "Windows"
	case "linux":
		return "Linux"
	}
	return p
}

// choosePackages picks EasyPatch's newest packages for a platform and
// architecture.
func choosePackages(pkgs []AgentPackage, server, platform, arch string) []agentproto.EasyPatchPackage {
	var out []agentproto.EasyPatchPackage
	for _, f := range formats(platform) {
		for _, p := range pkgs {
			if !p.IsLatest || !strings.EqualFold(p.Format, f) || !strings.EqualFold(p.Architecture, arch) {
				continue
			}
			u := p.DownloadURL
			if !strings.HasPrefix(u, "https://") {
				u = server + "/" + strings.TrimLeft(u, "/")
			}
			out = append(out, agentproto.EasyPatchPackage{FileName: p.FileName, URL: u, Format: f, Arch: arch, Version: p.Version,
				Size: p.SizeBytes, SHA256: strings.ToLower(p.SHA256)})
			break
		}
	}
	return out
}

// caForAgent picks the certificate authority to send from the PEM in the
// settings: the self-signed one (the root) when there are several, the
// first otherwise; "" when there is none.
func caForAgent(bundle string) string {
	var first, root []byte
	rest := []byte(bundle)
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			continue
		}
		enc := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b.Bytes})
		if first == nil {
			first = enc
		}
		if root == nil && c.CheckSignatureFrom(c) == nil {
			root = enc
		}
	}
	if root != nil {
		return string(root)
	}
	return string(first)
}

// finish ends an attempt: succeeded when why is "", failed otherwise. A
// failed attempt's enrollment token is revoked.
func (s *Service) finish(ctx context.Context, deviceID, attempt uuid.UUID, why string) error {
	var token *uuid.UUID
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		state := InstallSucceeded
		if why != "" {
			state = InstallFailed
		}
		err := tx.QueryRow(ctx, `UPDATE easypatch_installs SET state = $3, error = $4, finished_at = now()
			WHERE device_id = $1 AND attempt_id = $2 AND state = 'sent' RETURNING token_id`,
			deviceID, attempt, state, cut(why, 1000)).Scan(&token)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err == nil && why != "" && token != nil {
		s.revoke(ctx, *token)
	}
	s.fleet.clear()
	return err
}

// revoke revokes an enrollment token, best effort: it expires within the
// hour anyway.
func (s *Service) revoke(ctx context.Context, id uuid.UUID) {
	_, cl, err := s.conn(ctx)
	if err != nil || cl == nil {
		return
	}
	if err := cl.RevokeEnrollmentToken(context.WithoutCancel(ctx), id, ""); err != nil && !IsStatus(err, http.StatusNotFound) {
		s.log.Warn("easypatch: revoking an enrollment token failed", "error", err, "token_id", id)
	}
}

// ---------------------------------------------------------------- sweeps

// SweepInstalls fails attempts the agent never reported, and has devices of
// organizations with automatic installs install the EasyPatch agent. It
// returns how many installs it started waiting.
func (s *Service) SweepInstalls(ctx context.Context) (int, error) {
	var tokens []uuid.UUID
	waiting := 0
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE easypatch_installs SET state = 'failed', finished_at = now(),
				error = 'The device''s agent did not say how the install went within 30 minutes.'
			WHERE state = 'sent' AND sent_at < $1 RETURNING token_id`, s.now().Add(-installTimeout))
		if err != nil {
			return err
		}
		for rows.Next() {
			var t *uuid.UUID
			if err := rows.Scan(&t); err != nil {
				return err
			}
			if t != nil {
				tokens = append(tokens, *t)
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		// A device qualifies the way ineligible() decides, in SQL.
		const qualifies = `NOT d.quick_assist AND d.agent_public_key IS NOT NULL AND d.platform IN ('windows', 'linux') AND d.agent_arch IN ('amd64', 'arm64')
			AND coalesce(i.data->'easyPatch'->>'status', 'NotEnrolled') = 'NotEnrolled'
			AND NOT EXISTS (SELECT 1 FROM easypatch_opt_outs o WHERE o.device_id = d.id)
			AND NOT EXISTS (SELECT 1 FROM easypatch_removals r WHERE r.device_id = d.id)`
		tag, err := tx.Exec(ctx, `INSERT INTO easypatch_installs (device_id, state, automatic)
			SELECT d.id, 'waiting', true FROM devices d
			JOIN easypatch_organizations l ON l.organization_id = d.organization_id AND l.auto_install
			JOIN device_inventory i ON i.device_id = d.id
			WHERE `+qualifies+` AND NOT EXISTS (SELECT 1 FROM easypatch_installs x WHERE x.device_id = d.id)
			ON CONFLICT (device_id) DO NOTHING`)
		if err != nil {
			return err
		}
		waiting += int(tag.RowsAffected())
		tag, err = tx.Exec(ctx, `UPDATE easypatch_installs x SET state = 'waiting', error = '', note = '', attempt_id = NULL, token_id = NULL,
				sent_at = NULL, finished_at = NULL
			FROM devices d
			JOIN easypatch_organizations l ON l.organization_id = d.organization_id AND l.auto_install
			JOIN device_inventory i ON i.device_id = d.id
			WHERE x.device_id = d.id AND x.automatic AND x.state = 'failed' AND x.attempts < $1 AND x.finished_at < $2 AND `+qualifies,
			autoAttempts, s.now().Add(-autoRetry))
		if err != nil {
			return err
		}
		waiting += int(tag.RowsAffected())
		return nil
	})
	for _, t := range tokens {
		s.revoke(ctx, t)
	}
	if len(tokens) > 0 || waiting > 0 {
		s.fleet.clear()
	}
	return waiting, err
}
