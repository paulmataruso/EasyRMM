package eptest

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"

	"github.com/google/uuid"
)

// RepairCompanion and CollectLogs (ADR-0069), as the engine takes them
// (JobService.CreateAsync, RepairCompanionPayload.IsValid): a target and a
// step from fixed lists, never a command; only agents that declare the
// capability are sent them; at most 256 KiB of diagnostics, apart from the
// message.

// MaxDiagnostics is the most bytes of diagnostics the engine accepts in a
// result (JobDiagnostics.MaxBytes).
const MaxDiagnostics = 256 * 1024

// CompanionRequest is what a RepairCompanion job asks for.
type CompanionRequest struct {
	Target, Step, ExpectedSHA256 string
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidCompanion is RepairCompanionPayload.IsValid: the EasyRMM agent may
// be restarted or repaired (the repair carries the SHA-256 the recovery copy
// must have, a restart none), MeshAgent only restarted.
func ValidCompanion(c CompanionRequest) bool {
	switch c.Target {
	case "easyrmm-agent":
		switch c.Step {
		case "restart":
			return c.ExpectedSHA256 == ""
		case "repair":
			return sha256Hex.MatchString(c.ExpectedSHA256)
		}
	case "meshagent":
		return c.Step == "restart" && c.ExpectedSHA256 == ""
	}
	return false
}

// repairCompanion answers POST /api/v1/endpoints/{id}/companion/repair.
func (s *Server) repairCompanion(w http.ResponseWriter, e *Endpoint, body map[string]any) {
	c := CompanionRequest{}
	c.Target, _ = body["target"].(string)
	c.Step, _ = body["step"].(string)
	c.ExpectedSHA256, _ = body["expectedSha256"].(string)
	if !ValidCompanion(c) {
		problem(w, 400, "validation_failed", "Choose the EasyRMM agent or MeshAgent, a step it supports and, for the EasyRMM agent's repair, the SHA-256 of its recovery copy.")
		return
	}
	s.companionJob(w, e, "RepairCompanion", c)
}

// collectLogs answers POST /api/v1/endpoints/{id}/collect-logs.
func (s *Server) collectLogs(w http.ResponseWriter, e *Endpoint) {
	s.companionJob(w, e, "CollectLogs", CompanionRequest{})
}

func (s *Server) companionJob(w http.ResponseWriter, e *Endpoint, typ string, c CompanionRequest) {
	switch {
	case e.Status != "Active":
		problem(w, 409, "endpoint_not_active", fmt.Sprintf("%s is not active.", e.Hostname))
		return
	case e.CannotRepairCompanion:
		problem(w, 409, "agent_upgrade_required", fmt.Sprintf("The EasyPatch agent on %s cannot do that. Update it first.", e.Hostname))
		return
	}
	for _, j := range s.jobs {
		if j.Endpoint == e.ID && j.Type == typ && j.Companion == c && slices.Contains(dedupeStatuses, j.Status) {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusConflict)
			_ = jsonEncode(w, map[string]any{"status": 409, "code": "duplicate_job", "detail": "An identical job is already queued or running for this endpoint.", "existingJobId": j.ID})
			return
		}
	}
	j := s.newJob(e, typ, nil)
	j.Companion = c
	w.Header().Set("Location", "/api/v1/jobs/"+j.ID.String())
	reply(w, 202, j.summary())
}

// SetJobResult ends a job as its agent's result would: the status, the
// message (or, for a failure, the error code and message) and the
// diagnostics, which are kept apart from the message. It says whether the
// engine took it: more than MaxDiagnostics bytes are refused.
func (s *Server) SetJobResult(id uuid.UUID, status, message, errorCode, diagnostics string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.job(id)
	if j == nil || len(diagnostics) > MaxDiagnostics {
		return false
	}
	j.Message = message
	if status == "Failed" {
		j.ErrorCode, j.ErrorMessage = errorCode, message
	}
	j.Diagnostics = diagnostics
	s.setStatus(j, status)
	return true
}
