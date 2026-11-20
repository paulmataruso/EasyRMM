package easypatchapi

// Policies at every level, and tags.

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

func (a *API) registerPolicies(r func(string, httpapi.HandlerFunc)) {
	// The default policy has no id; the others name their organization,
	// site, device or tag.
	r("GET /api/v1/patching/policies/default", a.policy)
	r("PUT /api/v1/patching/policies/default", a.savePolicy)
	r("DELETE /api/v1/patching/policies/default", a.resetPolicy)
	r("GET /api/v1/patching/policies/{level}/{id}", a.policy)
	r("PUT /api/v1/patching/policies/{level}/{id}", a.savePolicy)
	r("DELETE /api/v1/patching/policies/{level}/{id}", a.resetPolicy)

	r("GET /api/v1/patching/tags", a.tags)
	r("POST /api/v1/patching/tags", a.createTag)
	r("PUT /api/v1/patching/tags/{id}", a.updateTag)
	r("DELETE /api/v1/patching/tags/{id}", a.deleteTag)
	r("GET /api/v1/patching/tags/of/{level}/{id}", a.assignedTags)
	r("PUT /api/v1/patching/tags/of/{level}/{id}", a.setTags)
}

// policyLevel reads the level and id from the path; an unknown level is not
// found, like an unknown id.
func policyLevel(r *http.Request) (string, uuid.UUID, error) {
	level := r.PathValue("level")
	if level == "" {
		return easypatch.LevelDefault, uuid.Nil, nil
	}
	if l, err := easypatch.ParsePolicyLevel(level); err != nil || l == easypatch.LevelDefault {
		return "", uuid.Nil, apperr.NotFound()
	}
	id, err := httpapi.PathID(r)
	return level, id, err
}

func (a *API) policy(w http.ResponseWriter, r *http.Request) error {
	level, id, err := policyLevel(r)
	if err != nil {
		return err
	}
	v, err := a.svc.Policy(r.Context(), httpapi.Caller(r), level, id)
	return ok(w, v, err)
}

func (a *API) savePolicy(w http.ResponseWriter, r *http.Request) error {
	level, id, err := policyLevel(r)
	if err != nil {
		return err
	}
	var in easypatch.PolicyLayer
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := a.svc.SavePolicy(r.Context(), httpapi.Caller(r), level, id, in)
	return ok(w, v, err)
}

func (a *API) resetPolicy(w http.ResponseWriter, r *http.Request) error {
	level, id, err := policyLevel(r)
	if err != nil {
		return err
	}
	v, err := a.svc.ResetPolicy(r.Context(), httpapi.Caller(r), level, id)
	return ok(w, v, err)
}

func (a *API) tags(w http.ResponseWriter, r *http.Request) error {
	v, err := a.svc.Tags(r.Context(), httpapi.Caller(r))
	return ok(w, v, err)
}

func (a *API) createTag(w http.ResponseWriter, r *http.Request) error {
	var in easypatch.TagInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	t, err := a.svc.CreateTag(r.Context(), httpapi.Caller(r), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, t)
	return nil
}

func (a *API) updateTag(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in easypatch.TagInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	t, err := a.svc.UpdateTag(r.Context(), httpapi.Caller(r), id, in)
	return ok(w, t, err)
}

func (a *API) deleteTag(w http.ResponseWriter, r *http.Request) error {
	id, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	if err := a.svc.DeleteTag(r.Context(), httpapi.Caller(r), id); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) assignedTags(w http.ResponseWriter, r *http.Request) error {
	level, id, err := policyLevel(r)
	if err != nil {
		return err
	}
	v, err := a.svc.AssignedTags(r.Context(), httpapi.Caller(r), level, id)
	return ok(w, v, err)
}

func (a *API) setTags(w http.ResponseWriter, r *http.Request) error {
	level, id, err := policyLevel(r)
	if err != nil {
		return err
	}
	var in struct {
		TagIDs []uuid.UUID `json:"tagIds"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	v, err := a.svc.SetTags(r.Context(), httpapi.Caller(r), level, id, in.TagIDs)
	return ok(w, v, err)
}
