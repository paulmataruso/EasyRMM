package keystore

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Per-volume escrow states the console shows (ADR-0081 section 14, slice 1).
const (
	StateMissing  = "missing"
	StatePending  = "pending"
	StateVerified = "verified"
	StateStale    = "stale"
	StateConflict = "conflict"
)

// ProtectorState is one recovery-password protector and the state of its
// escrow. No key, ciphertext or fingerprint is shown.
type ProtectorState struct {
	ID         string     `json:"id"`
	State      string     `json:"state"`
	VerifiedAt *time.Time `json:"verifiedAt,omitempty"`
	UpdatedAt  *time.Time `json:"updatedAt,omitempty"`
}

// VolumeState is a volume and its escrow state: the worst of its protectors,
// and missing when it reports no recovery-password protector at all.
type VolumeState struct {
	ID         string           `json:"id"`
	Mount      string           `json:"mount"`
	Status     string           `json:"status"`
	State      string           `json:"state"`
	Protectors []ProtectorState `json:"protectors"`
	ReportedAt time.Time        `json:"reportedAt"`
}

// Summary is what the console shows of the keystore itself.
type Summary struct {
	State            string `json:"state"`
	Mode             string `json:"mode,omitempty"`
	RecoveryVerified bool   `json:"recoveryVerified"`
	Detail           string `json:"detail,omitempty"`
	// FileMode is the standing warning of the stand-in mode.
	FileMode bool `json:"fileMode"`
}

// DeviceEscrow is the escrow state of one device.
type DeviceEscrow struct {
	// Applicable is false for a device that cannot escrow here: not a
	// Windows device, or in an organization outside the dev scope.
	Applicable bool    `json:"applicable"`
	Keystore   Summary `json:"keystore"`
	// CanRead: the caller holds the read permission here (ADR-0081, slice 2).
	// TwoPerson: a read waits for a second person's approval.
	CanRead   bool          `json:"canRead"`
	TwoPerson bool          `json:"twoPerson"`
	Volumes   []VolumeState `json:"volumes"`
}

// SummaryOf turns the keystore's status into what the console shows.
func SummaryOf(st Status) Summary {
	return Summary{State: st.State, Mode: st.Mode, RecoveryVerified: st.RecoveryVerified, Detail: st.Detail, FileMode: st.Mode == ModeFile}
}

// rank orders states, worst first, for the volume's own.
var rank = map[string]int{StateConflict: 0, StateStale: 1, StateMissing: 2, StatePending: 3, StateVerified: 4}

// DeviceState is the per-volume escrow state of a device, for a caller who
// may view it.
func (s *Service) DeviceState(ctx context.Context, c access.Caller, deviceID uuid.UUID) (*DeviceEscrow, error) {
	if c.Principal == nil && !c.IsSystem() {
		return nil, apperr.Forbidden()
	}
	var org, site uuid.UUID
	var platform string
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id, site_id, platform FROM devices WHERE id = $1`, deviceID).Scan(&org, &site, &platform)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	if !c.Can(rbac.PermDeviceView, rbac.Site(org, site)) {
		return nil, apperr.NotFound()
	}
	out := &DeviceEscrow{Applicable: platform == "windows" && devscope.Allowed(org), Volumes: []VolumeState{}}
	out.Keystore = SummaryOf(s.CurrentStatus(ctx))
	out.CanRead = c.Principal != nil && c.Can(rbac.PermRecoveryKeyRead, rbac.Site(org, site))
	if out.CanRead {
		if on, err := s.twoPerson(ctx, org); err == nil {
			out.TwoPerson = on
		}
	}
	if !out.Applicable {
		return out, nil
	}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		vols, err := tx.Query(ctx, `SELECT volume_id, mount, status, protectors, reported_at FROM device_encrypted_volumes
			WHERE device_id = $1 ORDER BY mount, volume_id`, deviceID)
		if err != nil {
			return err
		}
		defer vols.Close()
		for vols.Next() {
			var v VolumeState
			var raw []byte
			if err := vols.Scan(&v.ID, &v.Mount, &v.Status, &raw, &v.ReportedAt); err != nil {
				return err
			}
			var ps []protectorRef
			if err := json.Unmarshal(raw, &ps); err != nil {
				return err
			}
			v.Protectors = make([]ProtectorState, 0, len(ps))
			for _, p := range ps {
				v.Protectors = append(v.Protectors, ProtectorState{ID: p.ID, State: StateMissing})
			}
			out.Volumes = append(out.Volumes, v)
		}
		return vols.Err()
	})
	if err != nil {
		return nil, err
	}
	err = s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT volume_id, protector_id, state, verified_at, updated_at FROM recovery_key_escrows
			WHERE device_id = $1 AND state IN ('pending', 'verified', 'stale', 'conflict')`, deviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var vol, prot, state string
			var verifiedAt *time.Time
			var updated time.Time
			if err := rows.Scan(&vol, &prot, &state, &verifiedAt, &updated); err != nil {
				return err
			}
			for i := range out.Volumes {
				if out.Volumes[i].ID != vol {
					continue
				}
				for j := range out.Volumes[i].Protectors {
					p := &out.Volumes[i].Protectors[j]
					if p.ID != prot {
						continue
					}
					// A conflict is shown over the verified record it sits
					// beside, so that it is seen; the verified one stays
					// current.
					if rank[state] < rank[p.State] || (state == StateVerified && p.State == StateMissing) {
						p.State = state
					}
					if state == StateVerified {
						p.VerifiedAt = verifiedAt
					}
					u := updated
					p.UpdatedAt = &u
				}
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	for i := range out.Volumes {
		v := &out.Volumes[i]
		v.State = StateMissing
		if len(v.Protectors) > 0 {
			v.State = StateVerified
			for _, p := range v.Protectors {
				if rank[p.State] < rank[v.State] {
					v.State = p.State
				}
			}
		}
	}
	return out, nil
}

// Platform returns the keystore's status for a caller who may manage
// platform settings, with the KEK versions' metadata.
func (s *Service) Platform(ctx context.Context, c access.Caller) (Status, error) {
	if !c.CanGlobal(rbac.PermSettingsManage) {
		return Status{}, apperr.Forbidden()
	}
	return s.RefreshStatus(ctx), nil
}
