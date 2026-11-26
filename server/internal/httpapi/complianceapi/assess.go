package complianceapi

import (
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess"
	"github.com/paulmataruso/easyrmm/server/internal/httpapi"
)

// registerAssess mounts the assessment workspace (ADR-0078, C5).
func (a *API) registerAssess(r func(pattern string, h httpapi.HandlerFunc)) {
	const base = "/api/v1/organizations/{id}/compliance/"
	r("GET /api/v1/compliance/templates", a.templates)
	r("GET "+base+"assessments", a.assessments)
	r("POST "+base+"assessments", a.assessCreate)
	r("GET "+base+"assessments/{aid}", a.assessGet)
	r("POST "+base+"assessments/{aid}/transition", a.assessTransition)
	r("POST "+base+"assessments/{aid}/new-draft", a.assessNewDraft)
	r("GET "+base+"assessments/{aid}/scope", a.scopeGet)
	r("PUT "+base+"assessments/{aid}/scope", a.scopePut)
	r("POST "+base+"assessments/{aid}/refresh", a.assessRefresh)
	r("GET "+base+"assessments/{aid}/requirements", a.reqList)
	r("GET "+base+"assessments/{aid}/requirements/{req}", a.reqGet)
	r("PUT "+base+"assessments/{aid}/requirements/{req}", a.reqPut)
	r("PUT "+base+"assessments/{aid}/requirements/{req}/objectives/{obj}", a.objPut)
	r("POST "+base+"assessments/{aid}/requirements/{req}/attestations", a.attest)
	r("GET "+base+"assessments/{aid}/poam", a.poamGet)
	r("POST "+base+"assessments/{aid}/poam/generate", a.poamGenerate)
	r("PUT "+base+"assessments/{aid}/poam/{pid}", a.poamPut)
	r("POST "+base+"assessments/{aid}/poam/{pid}/milestones", a.milestoneAdd)
	r("PUT "+base+"assessments/{aid}/poam/milestones/{mid}", a.milestonePut)
	r("GET "+base+"assessments/{aid}/ssp", a.sspGet)
	r("POST "+base+"assessments/{aid}/ssp/generate", a.sspGenerate)
	r("PUT "+base+"assessments/{aid}/ssp/sections/{pos}", a.sspPut)
	r("GET "+base+"assessments/{aid}/export", a.export)
	r("GET "+base+"evidence", a.evidenceList)
	r("POST "+base+"evidence", a.evidenceAdd)
	r("POST "+base+"evidence/link", a.evidenceLinkAdd)
	r("GET "+base+"evidence/{eid}/download", a.evidenceDownload)
	r("POST "+base+"evidence/{eid}/links", a.evidenceLink)
	r("POST "+base+"evidence/{eid}/supersede", a.evidenceSupersede)
}

// ids reads the organization and assessment from the path.
func ids(r *http.Request) (org, aid uuid.UUID, err error) {
	if org, err = httpapi.PathID(r); err != nil {
		return
	}
	aid, err = httpapi.PathUUID(r, "aid")
	return
}

func (a *API) templates(w http.ResponseWriter, r *http.Request) error {
	items, err := a.assess.Templates()
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[any]{Items: toAny(items)})
	return nil
}

func toAny[T any](in []T) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func (a *API) assessments(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	items, err := a.assess.List(r.Context(), httpapi.Caller(r), org)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[assess.Assessment]{Items: items})
	return nil
}

func (a *API) assessCreate(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in assess.CreateInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.assess.Create(r.Context(), httpapi.Caller(r), org, in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}

func (a *API) assessGet(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	out, err := a.assess.Get(r.Context(), httpapi.Caller(r), org, aid)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) assessTransition(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	var in struct {
		To string `json:"to"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.assess.Transition(r.Context(), httpapi.Caller(r), org, aid, in.To)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) assessNewDraft(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	out, err := a.assess.NewDraft(r.Context(), httpapi.Caller(r), org, aid)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}

func (a *API) scopeGet(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	out, err := a.assess.GetScope(r.Context(), httpapi.Caller(r), org, aid)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) scopePut(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	var in struct {
		Items []assess.ScopeInput `json:"items"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.assess.PutScope(r.Context(), httpapi.Caller(r), org, aid, in.Items)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) assessRefresh(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	out, err := a.assess.Refresh(r.Context(), httpapi.Caller(r), org, aid)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) reqList(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	items, err := a.assess.Requirements(r.Context(), httpapi.Caller(r), org, aid)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[assess.RequirementRow]{Items: items})
	return nil
}

func (a *API) reqGet(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	out, err := a.assess.Requirement(r.Context(), httpapi.Caller(r), org, aid, r.PathValue("req"))
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) reqPut(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	var in assess.RequirementUpdate
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := a.assess.UpdateRequirement(r.Context(), httpapi.Caller(r), org, aid, r.PathValue("req"), in); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) objPut(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	var in assess.ObjectiveSet
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := a.assess.SetObjective(r.Context(), httpapi.Caller(r), org, aid, r.PathValue("req"), r.PathValue("obj"), in); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) attest(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	var in assess.AttestInput
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.assess.Attest(r.Context(), httpapi.Caller(r), org, aid, r.PathValue("req"), in)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}

func (a *API) poamGet(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	out, err := a.assess.POAM(r.Context(), httpapi.Caller(r), org, aid)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) poamGenerate(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	n, err := a.assess.GeneratePOAM(r.Context(), httpapi.Caller(r), org, aid)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, map[string]int{"drafted": n})
	return nil
}

func (a *API) poamPut(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	pid, err := httpapi.PathUUID(r, "pid")
	if err != nil {
		return err
	}
	var in assess.POAMUpdate
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := a.assess.UpdatePOAM(r.Context(), httpapi.Caller(r), org, aid, pid, in); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) milestoneAdd(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	pid, err := httpapi.PathUUID(r, "pid")
	if err != nil {
		return err
	}
	var in struct {
		Title string  `json:"title"`
		Due   *string `json:"due"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.assess.AddMilestone(r.Context(), httpapi.Caller(r), org, aid, pid, in.Title, in.Due)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}

func (a *API) milestonePut(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	mid, err := httpapi.PathUUID(r, "mid")
	if err != nil {
		return err
	}
	var in struct {
		Done bool `json:"done"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := a.assess.SetMilestone(r.Context(), httpapi.Caller(r), org, aid, mid, in.Done); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) sspGet(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	out, err := a.assess.SSP(r.Context(), httpapi.Caller(r), org, aid)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) sspGenerate(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	out, err := a.assess.GenerateSSP(r.Context(), httpapi.Caller(r), org, aid)
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, out)
	return nil
}

func (a *API) sspPut(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	pos, err := strconv.Atoi(r.PathValue("pos"))
	if err != nil {
		return apperr.NotFound()
	}
	var in struct {
		Body string `json:"body"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := a.assess.UpdateSSPSection(r.Context(), httpapi.Caller(r), org, aid, pos, in.Body); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// sendFile writes a file as a download. It is always an attachment of an opaque type, so that a
// browser never renders what a person uploaded on the console's own origin.
func sendFile(w http.ResponseWriter, name, contentType string, body []byte, sha string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if sha != "" {
		w.Header().Set("X-Content-SHA256", sha)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = w.Write(body) //nolint:gosec // an attachment of an opaque type with nosniff: a browser saves it and never renders it
}

func (a *API) export(w http.ResponseWriter, r *http.Request) error {
	org, aid, err := ids(r)
	if err != nil {
		return err
	}
	f, err := a.assess.Export(r.Context(), httpapi.Caller(r), org, aid, r.URL.Query().Get("format"))
	if err != nil {
		return err
	}
	sendFile(w, f.Name, f.ContentType, f.Body, f.SHA256)
	return nil
}

func (a *API) evidenceList(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	items, err := a.assess.ListEvidence(r.Context(), httpapi.Caller(r), org, r.URL.Query().Get("all") != "1")
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusOK, httpapi.List[assess.EvidenceView]{Items: items})
	return nil
}

// evidenceInput reads a file upload: the body is the file, capped at 64 MiB, and the details are in the query.
func evidenceInput(w http.ResponseWriter, r *http.Request) (assess.EvidenceInput, error) {
	q := r.URL.Query()
	in := assess.EvidenceInput{Kind: q.Get("kind"), Title: q.Get("title"), FileName: q.Get("fileName"), ReqID: q.Get("reqId"), ObjID: q.Get("objId")}
	if in.Kind == "" {
		in.Kind = "upload"
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err == nil {
		in.MediaType = mt
	}
	if m := q.Get("mediaType"); m != "" {
		in.MediaType = m
	}
	var err error
	var id uuid.UUID
	if id, err = httpapi.QueryID(r, "assessmentId"); err != nil {
		return in, err
	}
	if id != uuid.Nil {
		in.AssessmentID = &id
	}
	var pid, sid uuid.UUID
	if pid, err = httpapi.QueryID(r, "poamId"); err != nil {
		return in, err
	}
	if pid != uuid.Nil {
		in.PoamID = &pid
	}
	if sid, err = httpapi.QueryID(r, "supersedes"); err != nil {
		return in, err
	}
	if sid != uuid.Nil {
		in.Supersedes = &sid
	}
	if e := q.Get("expiresAt"); e != "" {
		t, err := time.Parse(time.RFC3339, e)
		if err != nil {
			return in, apperr.Invalid("expiresAt", "Use a date and time like 2027-06-30T00:00:00Z.")
		}
		in.ExpiresAt = &t
	}
	in.Body = http.MaxBytesReader(w, r.Body, assess.MaxEvidenceBytes)
	return in, nil
}

func tooLarge(err error) error {
	if errors.Is(err, assess.ErrTooLarge) {
		return &httpapi.Error{Status: http.StatusRequestEntityTooLarge, Code: "body_too_large", Message: "An evidence file can be at most 64 MiB."}
	}
	return err
}

func (a *API) evidenceAdd(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	in, err := evidenceInput(w, r)
	if err != nil {
		return err
	}
	out, err := a.assess.AddEvidence(r.Context(), httpapi.Caller(r), org, in)
	if err != nil {
		return tooLarge(err)
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}

func (a *API) evidenceSupersede(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	eid, err := httpapi.PathUUID(r, "eid")
	if err != nil {
		return err
	}
	in, err := evidenceInput(w, r)
	if err != nil {
		return err
	}
	in.Supersedes = &eid
	out, err := a.assess.AddEvidence(r.Context(), httpapi.Caller(r), org, in)
	if err != nil {
		return tooLarge(err)
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}

func (a *API) evidenceLinkAdd(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	var in struct {
		Title        string     `json:"title"`
		URL          string     `json:"url"`
		AssessmentID *uuid.UUID `json:"assessmentId"`
		ReqID        string     `json:"reqId"`
		ObjID        string     `json:"objId"`
		PoamID       *uuid.UUID `json:"poamId"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	out, err := a.assess.AddEvidence(r.Context(), httpapi.Caller(r), org, assess.EvidenceInput{Kind: "link", Title: in.Title, URL: in.URL,
		AssessmentID: in.AssessmentID, ReqID: in.ReqID, ObjID: in.ObjID, PoamID: in.PoamID})
	if err != nil {
		return err
	}
	httpapi.WriteJSON(w, http.StatusCreated, out)
	return nil
}

func (a *API) evidenceLink(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	eid, err := httpapi.PathUUID(r, "eid")
	if err != nil {
		return err
	}
	var in struct {
		AssessmentID *uuid.UUID `json:"assessmentId"`
		ReqID        string     `json:"reqId"`
		ObjID        string     `json:"objId"`
		PoamID       *uuid.UUID `json:"poamId"`
	}
	if err := httpapi.DecodeJSON(w, r, &in); err != nil {
		return err
	}
	if err := a.assess.LinkEvidence(r.Context(), httpapi.Caller(r), org, eid, in.AssessmentID, in.ReqID, in.ObjID, in.PoamID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (a *API) evidenceDownload(w http.ResponseWriter, r *http.Request) error {
	org, err := httpapi.PathID(r)
	if err != nil {
		return err
	}
	eid, err := httpapi.PathUUID(r, "eid")
	if err != nil {
		return err
	}
	d, err := a.assess.DownloadEvidence(r.Context(), httpapi.Caller(r), org, eid)
	if err != nil {
		return err
	}
	name := d.FileName
	if name == "" {
		name = fmt.Sprintf("evidence-%s", d.ID.String()[:8])
	}
	sendFile(w, name, "application/octet-stream", d.Body, d.SHA256)
	return nil
}
