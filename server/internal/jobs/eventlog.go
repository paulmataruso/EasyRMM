package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/eventrules"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// The event viewer's reads (ADR-0068, slice 1): a Windows computer's event
// logs are read by a builtin of the agent, in a child process, from a signed
// input; its result comes back as JSON lines, which the server reads again
// from each event's XML before it keeps them.

const (
	// openQueriesPerDevice is how many event log runs may be open on one
	// device, all people together; one person has one open per operation.
	openQueriesPerDevice = 2
)

// EventlogRequest asks for one operation of the event viewer on a device.
// The server builds the query from these typed filters; nobody sends XPath.
type EventlogRequest struct {
	DeviceID   uuid.UUID              `json:"-"`
	Op         string                 `json:"op"`
	Channels   []string               `json:"channels"`
	Levels     []int                  `json:"levels"`
	IDs        []eventrules.IDRange   `json:"ids"`
	ExcludeIDs []eventrules.IDRange   `json:"excludeIds"`
	Providers  []string               `json:"providers"`
	Tasks      []int                  `json:"tasks"`
	Keywords   string                 `json:"keywords"`
	Time       *eventrules.TimeFilter `json:"time"`
	Text       string                 `json:"text"`
	Record     int64                  `json:"record"`
	Provider   string                 `json:"provider"`
	// Sensitive is the person's choice to see the Security log or command
	// lines and scripts; it takes effect only for one who holds
	// log.view_sensitive in the device's organization.
	Sensitive bool `json:"sensitive"`
	// PreviousRunID asks for the page after that run's: the filters and the
	// cursor are the server's, from its stored result.
	PreviousRunID *uuid.UUID `json:"previousRunId"`
}

// EventlogRun is what a new operation answers: the run to follow.
type EventlogRun struct {
	JobID     uuid.UUID `json:"jobId"`
	RunID     uuid.UUID `json:"runId"`
	Op        string    `json:"op"`
	Sensitive bool      `json:"sensitive"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func eventlogName(op string) string { return "Event log: " + op }

// eventlogAudit is what the record of an operation holds: where and what,
// never an event, and the text's length, not the text.
func eventlogAudit(in eventrules.Input) map[string]any {
	d := map[string]any{"operation": in.Op, "sensitive": in.Sensitive}
	if len(in.Channels) > 0 {
		d["channels"] = in.Channels
	}
	switch in.Op {
	case eventrules.OpQuery:
		d["levels"], d["providers"], d["tasks"] = in.Levels, in.Providers, in.Tasks
		d["ids"], d["excludeIds"] = idStrings(in.IDs), idStrings(in.ExcludeIDs)
		if in.Keywords != "" {
			d["keywords"] = in.Keywords
		}
		if in.Time != nil {
			d["time"] = in.Time
		}
		if in.Text != "" {
			d["textLength"] = utf8.RuneCountInString(in.Text)
		}
		d["limits"] = map[string]any{"events": eventrules.PageEvents, "bytes": eventrules.PageBytes, "read": eventrules.MaxRead, "seconds": eventrules.QuerySeconds}
	case eventrules.OpEvent:
		d["record"] = in.Record
	case eventrules.OpProvider:
		d["provider"] = in.Provider
	}
	return d
}

func idStrings(rs []eventrules.IDRange) []string {
	var out []string
	for _, r := range rs {
		if r.To == 0 || r.To == r.From {
			out = append(out, strconv.Itoa(r.From))
		} else {
			out = append(out, fmt.Sprintf("%d-%d", r.From, r.To))
		}
	}
	return out
}

// eventlogInput turns a request into the agent's input: channels
// deduplicated ignoring case, the version and the rules' version set.
func eventlogInput(r EventlogRequest) eventrules.Input {
	in := eventrules.Input{V: eventrules.InputVersion, Op: r.Op, Rules: eventrules.Version}
	switch r.Op {
	case eventrules.OpQuery:
		in.Channels = eventrules.DedupeChannels(r.Channels)
		in.Levels, in.IDs, in.ExcludeIDs, in.Providers, in.Tasks = r.Levels, r.IDs, r.ExcludeIDs, r.Providers, r.Tasks
		in.Keywords, in.Time, in.Text = r.Keywords, r.Time, r.Text
	case eventrules.OpEvent:
		in.Channels, in.Record = eventrules.DedupeChannels(r.Channels), r.Record
	case eventrules.OpProvider:
		in.Provider = r.Provider
	}
	return in
}

// refusalReason says what the server refuses before anything is sent, or "".
func eventlogRefusal(in eventrules.Input, holds bool, wants bool) string {
	for _, c := range in.Channels {
		if eventrules.ValidChannel(c) != nil {
			return "a channel name Windows refuses"
		}
		if eventrules.IsSecurity(c) && !holds {
			return "the Security log and its archives need permission to see the Security log"
		}
	}
	if wants && !holds {
		return "sensitive data needs permission to see command lines and scripts"
	}
	return ""
}

// CreateEventlogQuery starts one operation of the event viewer on a Windows
// device. The caller needs eventlog.view at the device's site; the Security
// log and sensitive data need log.view_sensitive from an organization-wide
// grant, and a request for them without it is refused and recorded. The
// device's agent must list the builtin, or the request is refused with the
// reason.
func (s *Service) CreateEventlogQuery(ctx context.Context, c access.Caller, req EventlogRequest) (*EventlogRun, error) {
	var org, site uuid.UUID
	var devName string
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id, site_id, name FROM devices WHERE id = $1`, req.DeviceID).Scan(&org, &site, &devName)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.Invalid("deviceIds", "The device does not exist or is not visible to you.")
	}
	if err != nil {
		return nil, err
	}
	holds := c.IsSystem() || c.Can(rbac.PermLogViewSensitive, rbac.Org(org))
	var input eventrules.Input
	page := req.PreviousRunID != nil
	if page {
		if req.Op != "" && req.Op != eventrules.OpQuery {
			return nil, apperr.Invalid("op", "Only a query has pages.")
		}
		if input, err = s.eventlogNextPage(ctx, c, req.DeviceID, *req.PreviousRunID); err != nil {
			return nil, err
		}
	} else {
		input = eventlogInput(req)
		if reason := eventlogRefusal(input, holds, req.Sensitive); reason != "" {
			s.recordEventlogRefusal(ctx, c, req.DeviceID, input, reason)
			return nil, apperr.Invalid("channels", "Refused by EasyRMM: "+reason+".")
		}
		input.Sensitive = req.Sensitive && holds
		if !input.Sensitive {
			for _, ch := range input.Channels {
				if eventrules.IsSecurity(ch) {
					return nil, apperr.Invalid("sensitive", "Ask for the Security log with sensitive data.")
				}
			}
		}
	}
	if err := input.Check(); err != nil {
		return nil, apperr.Invalid("input", strings.TrimPrefix(err.Error(), "eventrules: the event log input is not valid: "))
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	if len(body) > agentproto.MaxInputBytes {
		return nil, apperr.Invalid("input", "The request is too large.")
	}
	kind := Kinds[KindEventlogQuery]
	sp := &spec{
		kind: KindEventlogQuery, name: eventlogName(input.Op), args: []string{}, timeout: int(kind.Timeout.Seconds()),
		executor: ExecBuiltin, builtin: kind.Builtin, lane: agentproto.LaneQuick, input: body, ttl: kind.WaitDefault,
		auditAction: kind.AuditAction, details: eventlogAudit(input),
	}
	if page {
		sp.auditAction = ""
	}
	r := rule{perm: rbac.PermEventlogView, verb: "read event logs", platforms: kind.Platforms, runsOn: "The event viewer runs on",
		requires: kind.needs(), what: "the event viewer", cannot: "open the event viewer"}
	ids := []uuid.UUID{req.DeviceID}
	var canceled bool
	job, err := s.create(ctx, c, ids, 1, sp, func(ctx context.Context, tx pgx.Tx) ([]target, error) {
		ts, err := s.targets(ctx, tx, c, ids, r)
		if err != nil {
			return nil, err
		}
		for _, t := range ts {
			if !devscope.Allowed(t.org) {
				return nil, apperr.Invalid("deviceIds", t.name+" is in an organization that is outside the development scope, where event logs are not read.")
			}
		}
		if input.Op == eventrules.OpQuery {
			// A new filter, page or refresh from the same person cancels their
			// run still open on that device.
			tag, err := tx.Exec(ctx, `UPDATE job_runs r SET
					status = CASE WHEN r.status = 'running' THEN r.status ELSE 'canceled' END,
					finished_at = CASE WHEN r.status = 'running' THEN r.finished_at ELSE now() END,
					error = CASE WHEN r.status = 'running' THEN r.error ELSE 'Canceled by a newer search.' END,
					cancel_requested_at = now(), canceled_by = $3
				FROM jobs j WHERE j.id = r.job_id AND j.kind = $1 AND j.script_name = $4 AND j.created_by = $3 AND r.device_id = $2
				  AND r.status IN ('queued', 'sent', 'running') AND r.cancel_requested_at IS NULL`,
				KindEventlogQuery, req.DeviceID, c.Actor.ID, eventlogName(eventrules.OpQuery))
			if err != nil {
				return nil, err
			}
			canceled = tag.RowsAffected() > 0
		}
		var open int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM job_runs r JOIN jobs j ON j.id = r.job_id
			WHERE j.kind = $1 AND r.device_id = $2 AND r.status IN ('queued', 'sent', 'running') AND r.cancel_requested_at IS NULL`,
			KindEventlogQuery, req.DeviceID).Scan(&open); err != nil {
			return nil, err
		}
		if open >= openQueriesPerDevice {
			return nil, apperr.Conflict("searches_open", "Two searches are already open on "+devName+".")
		}
		return ts, nil
	})
	if err != nil {
		return nil, err
	}
	if canceled {
		s.hub.notify(req.DeviceID)
	}
	if len(job.Runs) != 1 {
		return nil, fmt.Errorf("jobs: an event log read has %d runs", len(job.Runs))
	}
	return &EventlogRun{JobID: job.ID, RunID: job.Runs[0].ID, Op: input.Op, Sensitive: input.Sensitive, ExpiresAt: job.ExpiresAt}, nil
}

// recordEventlogRefusal records that the server refused a request, as
// eventlog.refused, within the bound ADR-0063 sets. The record is best
// effort: the refusal stands if it cannot be written.
func (s *Service) recordEventlogRefusal(ctx context.Context, c access.Caller, device uuid.UUID, in eventrules.Input, reason string) {
	st := s.audit.Stamp(c.Actor)
	d := eventlogAudit(in)
	d["rule"] = reason
	b, _ := json.Marshal(d)
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT easyrmm_eventlog_refusal($1, $2, $3, $4, $5, $6::inet, $7, $8)`,
			device, st.At, st.ActorType, st.ActorID, st.ActorLabel, st.SourceIP, st.UserAgent, b)
		return err
	})
	if err != nil {
		s.log.Warn("jobs: recording a refused event log request failed", "error", err)
	}
}

// eventlogNextPage builds the input of the page after a run's: its stored
// filters with the cursor from its stored result, through the definer
// function that checks the caller asked for that run, on this device, within
// the hour.
func (s *Service) eventlogNextPage(ctx context.Context, c access.Caller, device, prev uuid.UUID) (eventrules.Input, error) {
	view, sens := scopeOf(c, rbac.PermEventlogView), scopeOf(c, rbac.PermLogViewSensitive)
	st := s.audit.Stamp(c.Actor)
	var result string
	var raw, last []byte
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT result, prev_input, last_line FROM easyrmm_eventlog_page($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::inet, $14)`,
			prev, device, view.All, view.Orgs, view.Sites, sens.All, sens.Orgs, sens.Sites,
			st.At, st.ActorType, st.ActorID, st.ActorLabel, st.SourceIP, st.UserAgent).Scan(&result, &raw, &last)
	})
	if err != nil {
		return eventrules.Input{}, err
	}
	switch result {
	case "ok":
	case "expired":
		return eventrules.Input{}, apperr.Conflict("page_expired", "That search is too old to continue: search again.")
	default:
		return eventrules.Input{}, readResult(result)
	}
	in, err := eventrules.DecodeInput(raw)
	if err != nil {
		return in, fmt.Errorf("jobs: the stored input of run %s does not decode: %w", prev, err)
	}
	var end eventrules.End
	if err := json.Unmarshal(last, &end); err != nil || end.T != eventrules.LineEnd {
		return in, apperr.Conflict("page_incomplete", "That search did not finish, so there is no page after it: search again.")
	}
	if end.Cursor == nil {
		return in, apperr.Conflict("no_more", "There are no more events.")
	}
	more := false
	for _, ch := range end.Cursor.Channels {
		more = more || !ch.Done
	}
	if !more {
		return in, apperr.Conflict("no_more", "There are no more events.")
	}
	in.Cursor = end.Cursor
	return in, nil
}

// EventlogResultView is a result for the console: what the agent read, or
// why there is nothing to show.
type EventlogResultView struct {
	// State is "reported", "unavailable" (Windows denied access, or the
	// service is not running), "not_found", "refused" (EasyRMM's rule) or
	// "unknown", with Reason.
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Complete is false for a result without its end, or one the agent cut.
	Complete  bool   `json:"complete"`
	Kind      string `json:"kind"`
	RunStatus string `json:"runStatus"`
	Op        string `json:"op,omitempty"`
	// Sensitive says the query asked for sensitive data and may have it.
	Sensitive    bool       `json:"sensitive"`
	ReadAt       *time.Time `json:"readAt,omitempty"`
	AgentVersion string     `json:"agentVersion,omitempty"`
	Rules        int        `json:"rules,omitempty"`
	// Clock is the computer's clock when it ran.
	Clock    string                   `json:"clock,omitempty"`
	Arch     string                   `json:"arch,omitempty"`
	Crash    *eventrules.Crash        `json:"crash,omitempty"`
	Channels []eventrules.ChannelInfo `json:"channels,omitempty"`
	Pos      []eventrules.Pos         `json:"pos,omitempty"`
	Provider *eventrules.ProviderLine `json:"provider,omitempty"`
	Events   []eventrules.Event       `json:"events,omitempty"`
	End      *eventrules.End          `json:"end,omitempty"`
	Errors   []eventrules.ErrorLine   `json:"errors,omitempty"`
}

func stateOfEventlogErrors(errs []eventrules.ErrorLine) (state, reason string) {
	if len(errs) == 0 {
		return "", ""
	}
	e := errs[0]
	switch e.Code {
	case eventrules.ErrCodeDenied, eventrules.ErrCodeUnavailable:
		return "unavailable", e.Message
	case eventrules.ErrCodeNotFound:
		return "not_found", e.Message
	case eventrules.ErrCodeRefused:
		return "refused", e.Message
	}
	return "unknown", e.Message
}

// ReadEventlogResult returns a finished operation's result to the person who
// asked, when they hold eventlog.view and job.view_sensitive at the device's
// site, and log.view_sensitive in its organization if the query asked for
// sensitive data. A person who sees the run but may not read it is refused,
// and recorded as denied within ADR-0063's bound. A run in progress answers
// run_open.
func (s *Service) ReadEventlogResult(ctx context.Context, c access.Caller, id uuid.UUID) (*EventlogResultView, error) {
	var (
		result              string
		raw                 []byte
		complete            *bool
		runStatus           *string
		runErr, agent, kind *string
		started, finished   *time.Time
	)
	kindDef := Kinds[KindEventlogQuery]
	read := scopeOf(c, kindDef.ReadPerm)
	var askerOnly []string
	record := map[string]string{}
	for _, k := range builtinKinds() {
		if k.RecordRead != "" {
			record[k.Name] = k.RecordRead
		}
		if k.AskerOnly {
			askerOnly = append(askerOnly, k.Name)
		}
	}
	recordJSON, _ := json.Marshal(record)
	sens := scopeOf(c, rbac.PermJobViewSensitive)
	logSens := scopeOf(c, rbac.PermLogViewSensitive)
	jv := scopeOf(c, rbac.PermJobView)
	st := s.audit.Stamp(c.Actor)
	var parsed *eventrules.Result
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT result, res, complete, run_status, run_error, started, finished, agent_version, job_kind
			FROM easyrmm_eventlog_result($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::inet, $18, $19, $20, $21)`,
			id, jv.All, jv.Orgs, jv.Sites, sens.All, sens.Orgs, sens.Sites, read.All, read.Orgs, read.Sites,
			askerOnly, recordJSON, st.At, st.ActorType, st.ActorID, st.ActorLabel, st.SourceIP, st.UserAgent,
			logSens.All, logSens.Orgs, logSens.Sites).
			Scan(&result, &raw, &complete, &runStatus, &runErr, &started, &finished, &agent, &kind); err != nil {
			return err
		}
		if result != "ok" {
			return nil
		}
		var lines []json.RawMessage
		if err := json.Unmarshal(raw, &lines); err != nil {
			return fmt.Errorf("jobs: a stored event log result does not decode: %w", err)
		}
		bl := make([][]byte, len(lines))
		for i, l := range lines {
			bl[i] = l
		}
		var perr error
		if parsed, perr = eventrules.ParseLines(bl); perr != nil {
			return fmt.Errorf("jobs: a stored event log result does not decode: %w", perr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	switch result {
	case "ok":
	case "empty":
		v := &EventlogResultView{State: "unknown", RunStatus: deref(runStatus), Reason: emptyReason(deref(runStatus), deref(runErr))}
		if kind != nil {
			v.Kind = *kind
		}
		return v, nil
	default:
		if err := readResult(result); err != nil {
			return nil, err
		}
	}
	v := &EventlogResultView{State: "reported", RunStatus: deref(runStatus), Kind: deref(kind), Complete: complete != nil && *complete && parsed.End != nil,
		Op: parsed.Begin.Op, ReadAt: finished, AgentVersion: parsed.Begin.AgentVersion, Rules: parsed.Begin.Rules, Clock: parsed.Begin.Clock,
		Arch: parsed.Begin.Arch, Crash: parsed.Crash, Channels: parsed.Channels, Pos: parsed.Pos, Provider: parsed.Provider,
		Events: parsed.Events, End: parsed.End, Errors: parsed.Errors}
	if state, reason := stateOfEventlogErrors(parsed.Errors); state != "" {
		v.State, v.Reason = state, reason
	} else if parsed.End == nil {
		v.State, v.Reason = "unknown", "The agent stopped before it finished reading; what it read is shown."
	}
	return v, nil
}

// storeEventlogResult checks a result against its input and keeps it. A
// result that does not match fails the run and is not stored; one that
// breaks a rule also fails the run and is recorded as
// eventlog.refused_on_device (ADR-0068, Where it is enforced).
func (s *Service) storeEventlogResult(ctx context.Context, tx pgx.Tx, run uuid.UUID, input []byte, raw []byte, cut bool,
	fail func(string) (bool, error)) (bool, error) {
	const bad = "The agent's result was not valid, so it was not kept."
	res, err := eventrules.ParseLines(agentproto.SplitResultLines(raw))
	if err != nil {
		return fail(bad)
	}
	inp, err := eventrules.DecodeInput(input)
	if err != nil {
		return false, fmt.Errorf("jobs: the stored input of run %s does not decode: %w", run, err)
	}
	verdict, err := eventrules.CheckResult(inp, res, s.now())
	if err != nil {
		return fail("The agent's result did not match the request, so it was not kept: " + err.Error() + ".")
	}
	if len(verdict.Violations) > 0 {
		if err := s.recordEventlogRefusedOnDevice(ctx, tx, run, verdict.Violations); err != nil {
			return true, err
		}
		return fail("The agent's result broke a rule of EasyRMM, so it was not kept.")
	}
	lines, err := res.Lines()
	if err != nil {
		return true, err
	}
	doc, err := json.Marshal(lines)
	if err != nil {
		return true, err
	}
	_, err = tx.Exec(ctx, `UPDATE job_runs SET result = $2, result_stored_at = now(), result_complete = $3
		WHERE id = $1 AND result_removed_at IS NULL`, run, doc, res.End != nil && res.End.Complete && !cut)
	return true, err
}

// recordEventlogRefusedOnDevice records eventlog.refused_on_device: a result
// broke a rule. The system is the actor and the person who asked is in the
// details; no event data is in the record.
func (s *Service) recordEventlogRefusedOnDevice(ctx context.Context, tx pgx.Tx, run uuid.UUID, rules []string) error {
	var org, site, device uuid.UUID
	var name, asker string
	if err := tx.QueryRow(ctx, `SELECT r.organization_id, r.site_id, r.device_id, d.name, j.created_by_label
		FROM job_runs r JOIN jobs j ON j.id = r.job_id JOIN devices d ON d.id = r.device_id WHERE r.id = $1`, run).
		Scan(&org, &site, &device, &name, &asker); err != nil {
		return err
	}
	for _, rl := range slices.Clone(rules) {
		if err := s.audit.Write(ctx, tx, audit.Event{
			Actor: audit.SystemActor("eventlog"), Action: "eventlog.refused_on_device", Outcome: audit.Denied,
			OrganizationID: org, SiteID: site, DeviceID: device, TargetType: "job_run", TargetID: run.String(),
			Details: map[string]any{"device": name, "rule": rl, "askedBy": asker},
		}); err != nil {
			return err
		}
	}
	return nil
}
