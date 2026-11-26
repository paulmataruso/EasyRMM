package complianceapi

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/engine"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/fix"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// registerFix mounts the results views and the fix queue (ADR-0078, C2).
func (a *API) registerFix(r func(pattern string, h httpapi.HandlerFunc)) {
	r("GET /api/v1/organizations/{id}/compliance/summary", a.orgSummary)
	r("GET /api/v1/sites/{id}/compliance/summary", a.siteSummary)
	r("GET /api/v1/organizations/{id}/compliance/fixes", a.fixes)
	r("POST /api/v1/organizations/{id}/compliance/fixes/apply", a.fixApply)
	r("GET /api/v1/organizations/{id}/compliance/fixes/{itemId}", a.fixGet)
	r("POST /api/v1/organizations/{id}/compliance/fixes/{itemId}/undo", a.fixUndo)
	r("POST /api/v1/organizations/{id}/compliance/fixes/{itemId}/approve", a.fixApprove)
	r("POST /api/v1/organizations/{id}/compliance/fixes/{itemId}/decline", a.fixDecline)
	r("POST /api/v1/organizations/{id}/compliance/fixes/{itemId}/reopen", a.fixReopen)
	r("GET /api/v1/organizations/{id}/compliance/fix-settings", a.fixSettings)
	r("PUT /api/v1/organizations/{id}/compliance/fix-settings", a.putFixSettings)
	r("GET /api/v1/devices/{id}/compliance/fixes", a.deviceFixes)
	r("GET /api/v1/devices/{id}/compliance/frameworks/{key}", a.deviceFramework)
}

func (a *API) orgSummary(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.svc.Summarize(r.Context(), httpapi.Caller(r), id, uuid.Nil)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

// siteSummary needs the site's organization: it is read from the site, and
// the permission is then checked in that organization.
func (a *API) siteSummary(w http.ResponseWriter, r *http.Request) error {
	site, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	c := httpapi.Caller(r)
	org, err := a.svc.SiteOrg(r.Context(), c, site)
	if err != nil {
		return err
	}
	out, err := a.svc.Summarize(r.Context(), c, org, site)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) fixes(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	f, err := fixFilter(r)
	if err != nil {
		return err
	}
	items, err := a.fix.Queue(r.Context(), httpapi.Caller(r), org, f)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[fix.Item]{Items: items})
	return nil
}

func fixFilter(r *http.Request) (fix.Filter, error) {
	q := r.URL.Query()
	f := fix.Filter{State: q.Get("state"), Tier: q.Get("tier")}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return f, apperr.Invalid("limit", "Enter a number.")
		}
		f.Limit = n
	}
	for name, dst := range map[string]*uuid.UUID{"deviceId": &f.DeviceID, "siteId": &f.SiteID} {
		if v := q.Get(name); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				return f, apperr.Invalid(name, "Enter an id.")
			}
			*dst = id
		}
	}
	if f.Tier != "" && f.Tier != fix.T1 && f.Tier != fix.T2 && f.Tier != fix.T3 {
		return f, apperr.Invalid("tier", "Choose T1, T2 or T3.")
	}
	return f, nil
}

func (a *API) fixGet(w http.ResponseWriter, r *http.Request) error {
	org, item, err := orgAndItem(r)
	if err != nil {
		return err
	}
	out, err := a.fix.Get(r.Context(), httpapi.Caller(r), org, item)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func orgAndItem(r *http.Request) (org, item uuid.UUID, err error) {
	if org, err = httpapi.PathID(r); err != nil {
		return
	}
	item, err = httpapi.PathUUID(r, "itemId")
	return
}

func (a *API) fixApply(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in fix.ApplyInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	items, err := a.fix.Apply(r.Context(), httpapi.Caller(r), org, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[fix.Item]{Items: items})
	return nil
}

func (a *API) fixUndo(w http.ResponseWriter, r *http.Request) error {
	org, item, err := orgAndItem(r)
	if err != nil {
		return err
	}
	var in fix.Agreement
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.fix.Undo(r.Context(), httpapi.Caller(r), org, item, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) fixApprove(w http.ResponseWriter, r *http.Request) error {
	org, item, err := orgAndItem(r)
	if err != nil {
		return err
	}
	var in fix.Agreement
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.fix.Approve(r.Context(), httpapi.Caller(r), org, item, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) fixDecline(w http.ResponseWriter, r *http.Request) error {
	org, item, err := orgAndItem(r)
	if err != nil {
		return err
	}
	var in fix.DeclineInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.fix.Decline(r.Context(), httpapi.Caller(r), org, item, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) fixReopen(w http.ResponseWriter, r *http.Request) error {
	org, item, err := orgAndItem(r)
	if err != nil {
		return err
	}
	out, err := a.fix.Reopen(r.Context(), httpapi.Caller(r), org, item)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) fixSettings(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	out, err := a.fix.GetSettings(r.Context(), httpapi.Caller(r), org)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) putFixSettings(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in fix.Settings
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.fix.PutSettings(r.Context(), httpapi.Caller(r), org, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) deviceFixes(w http.ResponseWriter, r *http.Request) error {
	dev, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	c := httpapi.Caller(r)
	org, err := a.svc.DeviceOrg(r.Context(), c, dev)
	if err != nil {
		return err
	}
	f, err := fixFilter(r)
	if err != nil {
		return err
	}
	f.DeviceID = dev
	items, err := a.fix.Queue(r.Context(), c, org, f)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[fix.Item]{Items: items})
	return nil
}

func (a *API) deviceFramework(w http.ResponseWriter, r *http.Request) error {
	dev, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	c := httpapi.Caller(r)
	org, err := a.svc.DeviceOrg(r.Context(), c, dev)
	if err != nil {
		return err
	}
	var out *engine.FrameworkStatus
	if out, err = a.svc.FrameworkForDevice(r.Context(), c, org, dev, r.PathValue("key")); err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}
