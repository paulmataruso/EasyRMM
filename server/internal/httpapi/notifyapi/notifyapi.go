// Package notifyapi exposes notification channels, their tests and secrets,
// sharing, approvals, quotas, the delivery log and notices (ADR-0053).
// Who may do what is decided by the notify service, with
// notification.manage in the channel's organization, or a super
// administrator's for the platform's.
package notifyapi

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
	"github.com/paulmataruso/easyrmm/server/internal/notify"
)

// API serves the notification routes.
type API struct{ svc *notify.Service }

// New builds the API.
func New(svc *notify.Service) *API { return &API{svc: svc} }

// Register mounts the routes. Every one needs a fully signed-in session.
func (a *API) Register(mux *http.ServeMux) {
	r := func(pattern string, h httpapi.HandlerFunc) {
		mux.Handle(pattern, httpapi.RequireActive(httpapi.Handle(h)))
	}
	r("GET /api/v1/notifications/channels", a.list)
	r("POST /api/v1/notifications/channels", a.create)
	r("GET /api/v1/notifications/channels/{id}", a.get)
	r("PUT /api/v1/notifications/channels/{id}", a.update)
	r("DELETE /api/v1/notifications/channels/{id}", a.del)
	r("POST /api/v1/notifications/channels/{id}/test", a.test)
	r("POST /api/v1/notifications/channels/{id}/reveal", a.reveal)
	r("POST /api/v1/notifications/channels/{id}/rotate-secret", a.rotate)
	r("PUT /api/v1/notifications/channels/{id}/shares/{orgId}", a.share)
	r("DELETE /api/v1/notifications/channels/{id}/shares/{orgId}", a.unshare)
	r("POST /api/v1/notifications/channels/{id}/approval", a.ask)
	r("POST /api/v1/notifications/channels/{id}/approval/approve", a.approve)
	r("DELETE /api/v1/notifications/channels/{id}/approval", a.withdraw)
	r("GET /api/v1/notifications/approvals", a.requests)
	r("GET /api/v1/notifications/deliveries", a.deliveries)
	r("GET /api/v1/notifications/quotas/{orgId}", a.getQuota)
	r("PUT /api/v1/notifications/quotas/{orgId}", a.setQuota)
	r("GET /api/v1/notices", a.notices)
	r("POST /api/v1/notices/{id}/acknowledge", a.acknowledge)
	a.registerRules(mux)
}

// orgParam reads the optional organizationId query parameter.
func orgParam(r *http.Request) (*uuid.UUID, error) {
	id, err := httpapi.QueryID(r, "organizationId")
	if err != nil || id == uuid.Nil {
		return nil, err
	}
	return &id, nil
}

func (a *API) list(w http.ResponseWriter, r *http.Request) error {
	org, err := orgParam(r)
	if err != nil {
		return err
	}
	out, err := a.svc.List(r.Context(), httpapi.Caller(r), org)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"channels": out})
	return nil
}

func (a *API) create(w http.ResponseWriter, r *http.Request) error {
	var in notify.ChannelInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	ch, err := a.svc.Create(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, ch)
	return nil
}

func (a *API) get(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	ch, err := a.svc.Get(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, ch)
	return nil
}

func (a *API) update(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in notify.ChannelInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	ch, err := a.svc.Update(r.Context(), httpapi.Caller(r), id, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, ch)
	return nil
}

func (a *API) del(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.Delete(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// test answers 429 test_rate_limited, as the engine does, when a test went
// less than 30 seconds ago.
func (a *API) test(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	res, err := a.svc.Test(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, res)
	return nil
}

// reveal shows a webhook's address and signing secret again, never cached.
func (a *API) reveal(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	s, err := a.svc.Reveal(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	httpapi.WriteJSON(w, http.StatusOK, s)
	return nil
}

func (a *API) rotate(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.RotateSecret(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) share(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	org, err := httpapi.PathUUID(r, "orgId")
	if err != nil {
		return err
	}
	if err := a.svc.Share(r.Context(), httpapi.Caller(r), id, org); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) unshare(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	org, err := httpapi.PathUUID(r, "orgId")
	if err != nil {
		return err
	}
	if err := a.svc.Unshare(r.Context(), httpapi.Caller(r), id, org); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) ask(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	ap, err := a.svc.RequestApproval(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, ap)
	return nil
}

func (a *API) approve(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in struct {
		Prefixes []string `json:"prefixes"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	ap, err := a.svc.Approve(r.Context(), httpapi.Caller(r), id, in.Prefixes)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, ap)
	return nil
}

func (a *API) withdraw(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.Withdraw(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) requests(w http.ResponseWriter, r *http.Request) error {
	out, err := a.svc.Requests(r.Context(), httpapi.Caller(r))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"requests": out})
	return nil
}

func (a *API) deliveries(w http.ResponseWriter, r *http.Request) error {
	org, err := orgParam(r)
	if err != nil {
		return err
	}
	var channel *uuid.UUID
	if id, err := httpapi.QueryID(r, "channelId"); err != nil {
		return err
	} else if id != uuid.Nil {
		channel = &id
	}
	limit, err := httpapi.QueryCount(r, "limit", 100, 1, 500)
	if err != nil {
		return err
	}
	status := r.URL.Query().Get("status")
	switch status {
	case "", notify.StatusPending, notify.StatusSent, notify.StatusFailed, notify.StatusDropped:
	default:
		return apperr.Invalid("status", "Use pending, sent, failed or dropped.")
	}
	out, err := a.svc.Deliveries(r.Context(), httpapi.Caller(r), org, channel, status, limit)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"deliveries": out, "retentionDays": int(notify.DeliveryRetention / (24 * time.Hour))})
	return nil
}

func (a *API) getQuota(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathUUID(r, "orgId")
	if err != nil {
		return err
	}
	q, err := a.svc.GetQuota(r.Context(), httpapi.Caller(r), org)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, q)
	return nil
}

func (a *API) setQuota(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathUUID(r, "orgId")
	if err != nil {
		return err
	}
	var in notify.Quota
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	q, err := a.svc.SetQuota(r.Context(), httpapi.Caller(r), org, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, q)
	return nil
}

func (a *API) notices(w http.ResponseWriter, r *http.Request) error {
	org, err := orgParam(r)
	if err != nil {
		return err
	}
	out, err := a.svc.Notices(r.Context(), httpapi.Caller(r), org, r.URL.Query().Get("resolved") == "true")
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]any{"notices": out})
	return nil
}

func (a *API) acknowledge(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.Acknowledge(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
