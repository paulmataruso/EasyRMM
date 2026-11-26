package agentapi

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/auth"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/keystore"
)

// Escrow stores the recovery keys agents seal (keystore.Service, ADR-0081).
type Escrow interface {
	Instruction(ctx context.Context, d keystore.Device, platform string, caps []string) *agentproto.SignedEscrowKey
	ReportVolumes(ctx context.Context, d keystore.Device, rep agentproto.EscrowVolumesReport) (agentproto.EscrowVolumesAnswer, error)
	Upload(ctx context.Context, d keystore.Device, ip netip.Addr, rec agentproto.EscrowRecord) (agentproto.EscrowAnswer, error)
}

// escrowWait bounds one escrow request, which may call the keystore.
const escrowWait = 30 * time.Second

// An agent reports its volumes at most a few times an hour and uploads a
// record for a volume once in five minutes; the limit is a backstop.
const (
	escrowEvery = time.Minute
	escrowBurst = 10
)

// WithEscrow serves the recovery-key escrow routes from e and has heartbeats
// carry the organization's escrow key (ADR-0081).
func (a *API) WithEscrow(e Escrow) *API {
	a.escrow = e
	a.escrowLimit = auth.NewKeyedLimiter(escrowEvery, escrowBurst, maxTracked)
	return a
}

func escrowDevice(d *agents.Device) keystore.Device {
	return keystore.Device{ID: d.ID, Org: d.OrganizationID, Site: d.SiteID, Hostname: d.Hostname}
}

var (
	errEscrowFrequent = &httpapi.Error{Status: http.StatusTooManyRequests, Code: "rate_limited",
		Message: "This volume's recovery key was sent lately. Try again later.", RetryAfter: keystore.VolumeEvery}
	errEscrowKeyOutdated = &httpapi.Error{Status: http.StatusConflict, Code: "escrow_key_outdated",
		Message: "The record was sealed to an escrow key that is not the organization's current one. The next heartbeat carries the current key."}
	errEscrowNoKey = &httpapi.Error{Status: http.StatusConflict, Code: "escrow_key_missing",
		Message: "The organization has no escrow key yet."}
	errEscrowUnknown = &httpapi.Error{Status: http.StatusConflict, Code: "escrow_volume_unknown",
		Message: "The volume or its protector was not reported. Report the volumes first."}
	errEscrowOff = &httpapi.Error{Status: http.StatusNotFound, Code: "not_found", Message: "Not found."}
	errEscrowBad = &httpapi.Error{Status: http.StatusBadRequest, Code: "escrow_invalid",
		Message: "The escrow request is not valid."}
	errEscrowDown = &httpapi.Error{Status: http.StatusServiceUnavailable, Code: "keystore_unavailable",
		Message: "The keystore cannot take the record now. Try again later.", RetryAfter: time.Minute}
)

func mapEscrowError(err error) error {
	for from, to := range map[error]*httpapi.Error{
		keystore.ErrTooFrequent:    errEscrowFrequent,
		keystore.ErrKeyOutdated:    errEscrowKeyOutdated,
		keystore.ErrNoEscrowKey:    errEscrowNoKey,
		keystore.ErrUnknownVolume:  errEscrowUnknown,
		keystore.ErrOutOfScope:     errEscrowOff,
		keystore.ErrRecordMismatch: errEscrowBad,
		keystore.ErrUnavailable:    errEscrowDown,
		keystore.ErrNotReady:       errEscrowDown,
	} {
		if errors.Is(err, from) {
			return to
		}
	}
	return err
}

func (a *API) escrowVolumes(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	var in agentproto.EscrowVolumesReport
	if err := decode(r, body, &in); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), escrowWait)
	defer cancel()
	out, err := a.escrow.ReportVolumes(ctx, escrowDevice(d), in)
	if err != nil {
		return mapEscrowError(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) escrowUpload(w http.ResponseWriter, r *http.Request, d *agents.Device, body []byte) error {
	var in agentproto.EscrowRecord
	if err := decode(r, body, &in); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), escrowWait)
	defer cancel()
	out, err := a.escrow.Upload(ctx, escrowDevice(d), httpapi.ClientIP(r), in)
	if err != nil {
		return mapEscrowError(err)
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}
