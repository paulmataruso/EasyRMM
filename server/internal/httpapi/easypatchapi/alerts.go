package easypatchapi

// Patching → Alerts, and the alert rules and notification channels under
// Settings → Patching.

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

func (a *API) registerAlerts(r func(string, httpapi.HandlerFunc)) {
	r("GET /api/v1/patching/alerts", a.alerts)
	r("GET /api/v1/patching/alerts/summary", a.alertSummary)
	r("POST /api/v1/patching/alerts/acknowledge", a.acknowledgeAlerts)
	r("GET /api/v1/patching/alert-rules", a.alertRules)
	r("POST /api/v1/patching/alert-rules", a.createAlertRule)
	r("PUT /api/v1/patching/alert-rules/{id}", a.updateAlertRule)
	r("DELETE /api/v1/patching/alert-rules/{id}", a.deleteAlertRule)
	r("GET /api/v1/patching/notifications", a.notifications)
	r("PUT /api/v1/patching/notifications", a.setNotifications)
	r("GET /api/v1/patching/notifications/deliveries", a.deliveries)
	r("POST /api/v1/patching/notifications/channels", a.createChannel)
	r("PUT /api/v1/patching/notifications/channels/{id}", a.updateChannel)
	r("DELETE /api/v1/patching/notifications/channels/{id}", a.deleteChannel)
	r("POST /api/v1/patching/notifications/channels/{id}/test", a.testChannel)
	r("POST /api/v1/patching/notifications/channels/{id}/rotate-secret", a.rotateChannelSecret)
}

func (a *API) alerts(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	device, err := httpapi.QueryID(r, "deviceId")
	if err != nil {
		return err
	}
	v := r.URL.Query()
	list, err := a.svc.Alerts(r.Context(), httpapi.Caller(r), easypatch.AlertsQuery{OrganizationID: org, DeviceID: device,
		Status: v.Get("status"), Severity: v.Get("severity"), RuleType: v.Get("ruleType"), Search: v.Get("search")})
	return ok(w, list, err)
}

func (a *API) alertSummary(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.QueryID(r, "organizationId")
	if err != nil {
		return err
	}
	counts, err := a.svc.AlertCounts(r.Context(), httpapi.Caller(r), org)
	return ok(w, counts, err)
}

func (a *API) acknowledgeAlerts(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		AlertIDs []uuid.UUID `json:"alertIds"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	n, err := a.svc.AcknowledgeAlerts(r.Context(), httpapi.Caller(r), in.AlertIDs)
	return ok(w, map[string]int{"acknowledged": n}, err)
}

func (a *API) alertRules(w http.ResponseWriter, r *http.Request) error {
	list, err := a.svc.AlertRules(r.Context(), httpapi.Caller(r))
	return ok(w, list, err)
}

func (a *API) createAlertRule(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.AlertRuleRequest
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := a.svc.CreateAlertRule(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, v)
	return nil
}

func (a *API) updateAlertRule(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in easypatch.AlertRuleRequest
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := a.svc.UpdateAlertRule(r.Context(), httpapi.Caller(r), id, in)
	return ok(w, v, err)
}

func (a *API) deleteAlertRule(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteAlertRule(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) notifications(w http.ResponseWriter, r *http.Request) error {
	v, err := a.svc.Notifications(r.Context(), httpapi.Caller(r))
	return ok(w, v, err)
}

func (a *API) setNotifications(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.NotificationSettings
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := a.svc.SetNotificationSettings(r.Context(), httpapi.Caller(r), in)
	return ok(w, v, err)
}

func (a *API) deliveries(w http.ResponseWriter, r *http.Request) error {
	channel, err := httpapi.QueryID(r, "channelId")
	if err != nil {
		return err
	}
	page, err := httpapi.QueryCount(r, "page", 1, 1, 10_000)
	if err != nil {
		return err
	}
	p, err := a.svc.Deliveries(r.Context(), httpapi.Caller(r), easypatch.DeliveriesQuery{ChannelID: channel,
		Status: r.URL.Query().Get("status"), Page: page})
	return ok(w, p, err)
}

func (a *API) createChannel(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.ChannelRequest
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	saved, err := a.svc.CreateChannel(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, saved)
	return nil
}

func (a *API) updateChannel(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in easypatch.ChannelRequest
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	saved, err := a.svc.UpdateChannel(r.Context(), httpapi.Caller(r), id, in)
	return ok(w, saved, err)
}

func (a *API) deleteChannel(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteChannel(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) testChannel(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	d, err := a.svc.TestChannel(r.Context(), httpapi.Caller(r), id)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusAccepted, d)
	return nil
}

func (a *API) rotateChannelSecret(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	saved, err := a.svc.RotateChannelSecret(r.Context(), httpapi.Caller(r), id)
	return ok(w, saved, err)
}
