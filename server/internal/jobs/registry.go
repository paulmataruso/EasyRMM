package jobs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/registryrules"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// The registry editor's reads (ADR-0067, slice 1): a Windows computer's
// registry is read by a builtin of the agent, in a child process, from a
// signed input; its result comes back as JSON lines, which the server
// checks against the input before it keeps them.

// openReadsPerDevice is how many reads a person may have open on one device.
const openReadsPerDevice = 2

// RegistryQueryInput asks for one read of a device's registry. The path is
// typed (Hive, Path), or text the address bar holds (Text), which the server
// parses. The server sets the version and the rules' version.
type RegistryQueryInput struct {
	DeviceID uuid.UUID `json:"-"`
	Op       string    `json:"op"`
	Hive     string    `json:"hive"`
	View     string    `json:"view"`
	Path     []string  `json:"path"`
	// Text is a path in any of the spellings the address bar takes; when set
	// it replaces Hive and Path.
	Text       string                     `json:"text"`
	ValueName  *string                    `json:"valueName"`
	Cursor     *agentproto.RegistryCursor `json:"cursor"`
	MaxSubkeys int                        `json:"maxSubkeys"`
	MaxValues  int                        `json:"maxValues"`
	Term       string                     `json:"term"`
	Depth      int                        `json:"depth"`
	MaxMatches int                        `json:"maxMatches"`
}

// RegistryRun is what a new read answers: the run to follow, and the key
// asked for as the server read it.
type RegistryRun struct {
	JobID     uuid.UUID `json:"jobId"`
	RunID     uuid.UUID `json:"runId"`
	Op        string    `json:"op"`
	Hive      string    `json:"hive"`
	View      string    `json:"view"`
	Path      []string  `json:"path"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// normalizeRegistryInput turns the request into the agent's input, applying
// the address bar's spelling and the defaults.
func normalizeRegistryInput(in RegistryQueryInput) (agentproto.RegistryInput, error) {
	out := agentproto.RegistryInput{
		V: agentproto.RegistryInputVersion, Op: in.Op, Hive: in.Hive, View: in.View, Path: in.Path, ValueName: in.ValueName,
		Cursor: in.Cursor, MaxSubkeys: in.MaxSubkeys, MaxValues: in.MaxValues, Term: in.Term, Depth: in.Depth,
		MaxMatches: in.MaxMatches, Rules: registryrules.Version,
	}
	if out.View == "" {
		out.View = string(registryrules.View64)
	}
	if in.Text != "" {
		h, names, err := registryrules.ParseText(in.Text)
		switch {
		case errors.Is(err, registryrules.ErrCurrentUser):
			return out, apperr.Invalid("text", "HKEY_CURRENT_USER belongs to a user: open one of the loaded user hives under HKEY_USERS.")
		case err != nil:
			return out, apperr.Invalid("text", "That is not a registry path: "+strings.TrimPrefix(err.Error(), "registryrules: "))
		}
		out.Hive, out.Path = string(h), names
	}
	if out.Path == nil {
		out.Path = []string{}
	}
	if out.Op == agentproto.RegOpList {
		if out.MaxSubkeys == 0 {
			out.MaxSubkeys = agentproto.RegMaxSubkeys
		}
		if out.MaxValues == 0 {
			out.MaxValues = agentproto.RegMaxValues
		}
	}
	if out.Op == agentproto.RegOpSearch {
		if out.Depth == 0 {
			out.Depth = agentproto.RegDefaultDepth
		}
		if out.MaxMatches == 0 {
			out.MaxMatches = agentproto.RegMaxMatches
		}
	}
	if err := out.Check(); err != nil {
		return out, apperr.Invalid("input", strings.TrimPrefix(err.Error(), "agentproto: the registry input is not valid: "))
	}
	return out, nil
}

// registryAudit is what the record of a read holds: where and what, the
// search term's length and never the term.
func registryAudit(in agentproto.RegistryInput) map[string]any {
	path := strings.Join(in.Path, `\`)
	if r := []rune(path); len(r) > registryrules.MaxPathChars {
		path = string(r[:registryrules.MaxPathChars])
	}
	d := map[string]any{"hive": in.Hive, "view": in.View, "path": path, "operation": in.Op}
	switch in.Op {
	case agentproto.RegOpSearch:
		d["termLength"] = len([]rune(in.Term))
		d["depth"], d["maxMatches"] = in.Depth, in.MaxMatches
	case agentproto.RegOpList:
		d["maxSubkeys"], d["maxValues"] = in.MaxSubkeys, in.MaxValues
	}
	return d
}

// CreateRegistryQuery asks one Windows device to read its registry. The
// caller needs registry.view at the device's site; the input is checked
// as the agent will check it, and a refused path is refused here and
// recorded. The device's agent must list what the editor needs, or the read
// is refused with the reason.
func (s *Service) CreateRegistryQuery(ctx context.Context, c access.Caller, in RegistryQueryInput) (*RegistryRun, error) {
	input, err := normalizeRegistryInput(in)
	if err != nil {
		return nil, err
	}
	kind := Kinds[KindRegistryQuery]
	if r := input.Refused(); r != nil {
		s.recordRegistryRefusal(ctx, c, in.DeviceID, input, r)
		return nil, apperr.Invalid("path", "Refused by EasyRMM: "+r.Rule+". The registry editor never reads it.")
	}
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	if len(body) > agentproto.MaxInputBytes {
		return nil, apperr.Invalid("input", "The request is too large.")
	}
	lane := ""
	if kind.Quick {
		lane = agentproto.LaneQuick
	}
	sp := &spec{
		kind: KindRegistryQuery, name: "Registry read", args: []string{}, timeout: int(kind.Timeout.Seconds()),
		executor: ExecBuiltin, builtin: kind.Builtin, lane: lane, input: body, ttl: kind.WaitDefault,
		auditAction: kind.AuditAction, details: registryAudit(input),
	}
	r := rule{perm: rbac.PermRegistryView, verb: "read the registry", platforms: kind.Platforms, runsOn: "The registry editor runs on",
		requires: kind.needs(), what: "the registry editor", cannot: "open the registry editor"}
	ids := []uuid.UUID{in.DeviceID}
	job, err := s.create(ctx, c, ids, 1, sp, func(ctx context.Context, tx pgx.Tx) ([]target, error) {
		ts, err := s.targets(ctx, tx, c, ids, r)
		if err != nil {
			return nil, err
		}
		for _, t := range ts {
			if !devscope.Allowed(t.org) {
				return nil, apperr.Invalid("deviceIds", t.name+" is in an organization that is outside the development scope, where registry reads are not made.")
			}
		}
		var open int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM job_runs r JOIN jobs j ON j.id = r.job_id
			WHERE j.kind = $1 AND j.created_by = $2 AND r.device_id = $3 AND r.status IN ('queued', 'sent', 'running')`,
			KindRegistryQuery, c.Actor.ID, in.DeviceID).Scan(&open); err != nil {
			return nil, err
		}
		if open >= openReadsPerDevice {
			return nil, apperr.Conflict("reads_open", "Wait for the last read to finish.")
		}
		return ts, nil
	})
	if err != nil {
		return nil, err
	}
	if len(job.Runs) != 1 {
		return nil, fmt.Errorf("jobs: a registry read has %d runs", len(job.Runs))
	}
	return &RegistryRun{JobID: job.ID, RunID: job.Runs[0].ID, Op: input.Op, Hive: input.Hive, View: input.View, Path: input.Path,
		ExpiresAt: job.ExpiresAt}, nil
}

// recordRegistryRefusal records that the server refused a request for a
// refused path, as registry.refused, within the bound ADR-0063 sets. The
// record is best effort: the refusal stands if it cannot be written.
func (s *Service) recordRegistryRefusal(ctx context.Context, c access.Caller, device uuid.UUID, in agentproto.RegistryInput, r *registryrules.Refusal) {
	st := s.audit.Stamp(c.Actor)
	d := registryAudit(in)
	d["rule"] = r.Rule
	b, _ := json.Marshal(d)
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `SELECT easyrmm_registry_refusal($1, $2, $3, $4, $5, $6::inet, $7, $8)`,
			device, st.At, st.ActorType, st.ActorID, st.ActorLabel, st.SourceIP, st.UserAgent, b)
		return err
	})
	if err != nil {
		s.log.Warn("jobs: recording a refused registry path failed", "error", err)
	}
}

// RegistryResultView is a read's result for the console: what the agent
// read, or why there is nothing to show.
type RegistryResultView struct {
	// State is "reported", "unavailable" (Windows denied access), "not_found",
	// "refused" (EasyRMM's rule) or "unknown", with Reason.
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Complete is false for a result without its end, or one the agent cut.
	Complete  bool     `json:"complete"`
	Kind      string   `json:"kind"`
	RunStatus string   `json:"runStatus"`
	Op        string   `json:"op,omitempty"`
	Hive      string   `json:"hive,omitempty"`
	View      string   `json:"view,omitempty"`
	Path      []string `json:"path,omitempty"`
	// ReadAt is when the agent finished reading.
	ReadAt       *time.Time              `json:"readAt,omitempty"`
	AgentVersion string                  `json:"agentVersion,omitempty"`
	Rules        int                     `json:"rules,omitempty"`
	Key          *agentproto.RegKey      `json:"key,omitempty"`
	Subkeys      []agentproto.RegSubkey  `json:"subkeys,omitempty"`
	Values       []agentproto.RegValue   `json:"values,omitempty"`
	Matches      []agentproto.RegMatch   `json:"matches,omitempty"`
	End          *agentproto.RegEnd      `json:"end,omitempty"`
	Refused      []agentproto.RegRefused `json:"refused,omitempty"`
	// ExportKeys counts an export's keys; the file is downloaded.
	ExportKeys   int `json:"exportKeys,omitempty"`
	ExportValues int `json:"exportValues,omitempty"`
}

// stateOfErrors maps the agent's error line to a state.
func stateOfErrors(errs []agentproto.RegError) (state, reason string) {
	if len(errs) == 0 {
		return "", ""
	}
	e := errs[0]
	switch e.Code {
	case agentproto.ErrCodeDenied:
		return "unavailable", e.Message
	case agentproto.ErrCodeNotFound:
		return "not_found", e.Message
	case agentproto.ErrCodeRefused:
		return "refused", e.Message
	}
	return "unknown", e.Message
}

// readRegistry reads a run's result for the caller (see easyrmm_job_run_result).
func (s *Service) readRegistry(ctx context.Context, c access.Caller, id uuid.UUID, recordAction string, then func(pgx.Tx, *RegistryResultView, *agentproto.RegistryResult) error) (*RegistryResultView, *agentproto.RegistryResult, error) {
	var (
		result              string
		raw                 []byte
		complete            *bool
		runStatus           *string
		runErr, agent, kind *string
		started, finished   *time.Time
	)
	kindDef := Kinds[KindRegistryQuery]
	read := scopeOf(c, kindDef.ReadPerm)
	record := map[string]string{}
	var askerOnly []string
	for _, k := range builtinKinds() {
		if k.RecordRead != "" {
			record[k.Name] = k.RecordRead
		}
		if k.AskerOnly {
			askerOnly = append(askerOnly, k.Name)
		}
	}
	if recordAction != "" {
		record[KindRegistryQuery] = recordAction
	}
	recordJSON, _ := json.Marshal(record)
	var view *RegistryResultView
	var parsed *agentproto.RegistryResult
	query := `SELECT result, res, complete, run_status, run_error, started, finished, agent_version, job_kind
		FROM easyrmm_job_run_result($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::inet, $18)`
	sens := scopeOf(c, rbac.PermJobViewSensitive)
	jv := scopeOf(c, rbac.PermJobView)
	st := s.audit.Stamp(c.Actor)
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		// The kind of the run decides who may read: a query only its asker.
		if err := tx.QueryRow(ctx, query, id, jv.All, jv.Orgs, jv.Sites, sens.All, sens.Orgs, sens.Sites, read.All, read.Orgs, read.Sites,
			askerOnly, recordJSON, st.At, st.ActorType, st.ActorID, st.ActorLabel, st.SourceIP, st.UserAgent).
			Scan(&result, &raw, &complete, &runStatus, &runErr, &started, &finished, &agent, &kind); err != nil {
			return err
		}
		if result != "ok" {
			return nil
		}
		view = &RegistryResultView{State: "reported", Complete: complete != nil && *complete, RunStatus: deref(runStatus)}
		var lines []json.RawMessage
		if err := json.Unmarshal(raw, &lines); err != nil {
			return fmt.Errorf("jobs: a stored registry result does not decode: %w", err)
		}
		bl := make([][]byte, len(lines))
		for i, l := range lines {
			bl[i] = l
		}
		var perr error
		if parsed, perr = agentproto.ParseRegistryLines(bl); perr != nil {
			return fmt.Errorf("jobs: a stored registry result does not decode: %w", perr)
		}
		if finished != nil {
			view.ReadAt = finished
		}
		if then != nil {
			return then(tx, view, parsed)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	switch result {
	case "ok":
	case "empty":
		view = &RegistryResultView{State: "unknown", RunStatus: deref(runStatus)}
		view.Reason = emptyReason(deref(runStatus), deref(runErr))
		if kind != nil {
			view.Kind = *kind
		}
		return view, nil, nil
	default:
		if err := readResult(result); err != nil {
			return nil, nil, err
		}
	}
	if kind != nil {
		view.Kind = *kind
	}
	b := parsed.Begin
	view.Op, view.Hive, view.View, view.Path, view.Rules, view.AgentVersion = b.Op, b.Hive, b.View, b.Path, b.Rules, b.AgentVersion
	if finished != nil {
		view.ReadAt = finished
	}
	view.Key, view.Subkeys, view.Values, view.Matches, view.End, view.Refused = parsed.Key, parsed.Subkeys, parsed.Values, parsed.Matches, parsed.End, parsed.Refused
	view.Complete = view.Complete && parsed.End != nil
	for _, x := range parsed.XKeys {
		view.ExportKeys++
		view.ExportValues += len(x.Values)
	}
	if state, reason := stateOfErrors(parsed.Errors); state != "" {
		view.State, view.Reason = state, reason
	} else if parsed.End == nil {
		view.State, view.Reason = "unknown", "The agent stopped before it finished reading; what it read is shown."
	}
	return view, parsed, nil
}

// emptyReason says why a run that ended has no result to show.
func emptyReason(status, runErr string) string {
	switch status {
	case StatusSucceeded:
		return "The agent finished but sent no result."
	case StatusTimedOut:
		return "The read timed out on the device."
	case StatusCanceled:
		return "The read was canceled."
	case StatusExpired:
		if runErr != "" {
			return runErr
		}
		return "The device did not answer in time."
	}
	if runErr != "" {
		return runErr
	}
	return "The read did not finish."
}

// ReadRegistryResult returns a finished read's result to the person who
// asked, when they hold registry.view and job.view_sensitive at the
// device's site. A person who sees the run but may not read it is refused,
// and recorded as denied within ADR-0063's bound. A read in progress
// answers run_open.
func (s *Service) ReadRegistryResult(ctx context.Context, c access.Caller, id uuid.UUID) (*RegistryResultView, error) {
	v, _, err := s.readRegistry(ctx, c, id, "", nil)
	return v, err
}

// recordRegistryResult checks a result against its input and keeps it. A
// result that does not match fails the run and is not stored; one that holds
// a refused path also fails the run, and is recorded as
// registry.refused_on_device. It reports whether the run was a structured
// one at all (handled).
func (s *Service) recordRegistryResult(ctx context.Context, tx pgx.Tx, device, run uuid.UUID, in agentproto.ResultRequest) (handled bool, err error) {
	var kind *string
	var input []byte
	if err := tx.QueryRow(ctx, `SELECT job_kind, job_input FROM easyrmm_job_run_input_system($1)`, run).Scan(&kind, &input); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	if kind == nil || !isStructured(*kind) {
		return false, nil
	}
	if in.AgentVersion != "" {
		if _, err := tx.Exec(ctx, `UPDATE job_runs SET ran_agent_version = $2 WHERE id = $1`, run, truncateRunes(cleanText(in.AgentVersion, false), 64)); err != nil {
			return true, err
		}
	}
	if in.Result == "" {
		return true, nil // an older build dropped it: shown as unknown
	}
	fail := func(reason string) (bool, error) {
		_, err := tx.Exec(ctx, `UPDATE job_runs SET status = 'failed', error = $2, exit_code = NULL WHERE id = $1`, run, truncateRunes(reason, agentproto.MaxJobError))
		return true, err
	}
	raw, err := base64.StdEncoding.DecodeString(in.Result)
	if err != nil || len(raw) > agentproto.MaxResultFile {
		return fail("The agent's result was not valid, so it was not kept.")
	}
	if *kind == KindEventlogQuery {
		return s.storeEventlogResult(ctx, tx, run, input, raw, in.ResultCut, fail)
	}
	lines := agentproto.SplitResultLines(raw)
	res, perr := agentproto.ParseRegistryLines(lines)
	if perr != nil {
		return fail("The agent's result was not valid, so it was not kept.")
	}
	var inp agentproto.RegistryInput
	if json.Unmarshal(input, &inp) != nil {
		return false, fmt.Errorf("jobs: the stored input of run %s does not decode", run)
	}
	if err := checkRegistryResult(inp, res); err != nil {
		return fail("The agent's result did not match the request, so it was not kept: " + err.Error())
	}
	refused := refusedInResult(res)
	if len(refused) > 0 {
		if err := s.recordRefusedOnDevice(ctx, tx, run, refused); err != nil {
			return true, err
		}
	}
	for _, f := range res.Refused {
		// The agent refused what the server let through.
		if err := s.recordRefusedOnDevice(ctx, tx, run, []refusedPath{{Path: f.Path, Rule: f.Rule, Kernel: f.Kernel}}); err != nil {
			return true, err
		}
	}
	if len(refused) > 0 {
		return fail("The agent's result held a path EasyRMM refuses, so it was not kept.")
	}
	maskResult(res)
	stored := make([]json.RawMessage, 0, len(lines))
	for i := range lines {
		// A masked value's data may have been dropped: write the lines again
		// from what was decoded, not as received.
		b, err := encodeResultLine(res, i)
		if err != nil {
			return true, err
		}
		stored = append(stored, b)
	}
	doc, err := json.Marshal(stored)
	if err != nil {
		return true, err
	}
	_, err = tx.Exec(ctx, `UPDATE job_runs SET result = $2, result_stored_at = now(), result_complete = $3
		WHERE id = $1 AND result_removed_at IS NULL`, run, doc, res.End != nil && res.End.Complete && !in.ResultCut)
	return true, err
}

// refusedPath is a path a result shows to be refused.
type refusedPath struct {
	Path   []string
	Rule   string
	Kernel string
}

// refusedInResult lists the paths in a result that the server's rules
// refuse: the key of a listing, subkeys, matches and exported keys.
func refusedInResult(res *agentproto.RegistryResult) []refusedPath {
	var out []refusedPath
	h, v := registryrules.Hive(res.Begin.Hive), registryrules.View(res.Begin.View)
	check := func(path []string) {
		if r := registryrules.Check(h, v, path); r != nil {
			out = append(out, refusedPath{Path: path, Rule: r.Rule})
		}
	}
	for _, sk := range res.Subkeys {
		if sk.State == agentproto.StateRefused {
			continue // marked as refused, and not opened
		}
		check(append(append([]string{}, res.Begin.Path...), sk.Name))
	}
	for _, m := range res.Matches {
		check(m.Path)
	}
	for _, x := range res.XKeys {
		if x.State == agentproto.StateRefused {
			continue
		}
		check(x.Path)
	}
	if res.Key != nil {
		if hh, names, err := registryrules.ParseText(res.Key.Kernel); err == nil {
			if r := registryrules.Check(hh, v, names); r != nil {
				out = append(out, refusedPath{Path: res.Begin.Path, Rule: r.Rule, Kernel: res.Key.Kernel})
			}
		}
	}
	return out
}

// recordRefusedOnDevice records registry.refused_on_device: the server
// allowed what a result shows the agent refused, or the result holds a
// refused path. The system is the actor and the person who asked is in the
// details.
func (s *Service) recordRefusedOnDevice(ctx context.Context, tx pgx.Tx, run uuid.UUID, paths []refusedPath) error {
	var org, site, device uuid.UUID
	var name, asker string
	if err := tx.QueryRow(ctx, `SELECT r.organization_id, r.site_id, r.device_id, d.name, j.created_by_label
		FROM job_runs r JOIN jobs j ON j.id = r.job_id JOIN devices d ON d.id = r.device_id WHERE r.id = $1`, run).
		Scan(&org, &site, &device, &name, &asker); err != nil {
		return err
	}
	for _, p := range paths {
		path := strings.Join(p.Path, `\`)
		if r := []rune(path); len(r) > registryrules.MaxPathChars {
			path = string(r[:registryrules.MaxPathChars])
		}
		if err := s.audit.Write(ctx, tx, audit.Event{
			Actor: audit.SystemActor("registry"), Action: "registry.refused_on_device", Outcome: audit.Denied,
			OrganizationID: org, SiteID: site, DeviceID: device, TargetType: "job_run", TargetID: run.String(),
			Details: map[string]any{"device": name, "path": path, "rule": p.Rule, "kernel": p.Kernel, "askedBy": asker},
		}); err != nil {
			return err
		}
	}
	return nil
}

// checkRegistryResult checks a result against the input that asked for it:
// the operation, hive, view, path and cursor, counts within the input's
// limits, every key under the key asked for.
func checkRegistryResult(in agentproto.RegistryInput, res *agentproto.RegistryResult) error {
	b := res.Begin
	switch {
	case b.V != agentproto.RegistryResultVersion:
		return fmt.Errorf("result version %d is not known", b.V)
	case b.Op != in.Op || b.Hive != in.Hive || b.View != in.View || !equalPath(b.Path, in.Path):
		return errors.New("it is for another operation, hive, view or path")
	}
	underAsked := func(p []string) bool {
		if len(p) < len(in.Path) {
			return false
		}
		for i, n := range in.Path {
			if p[i] != n {
				return false
			}
		}
		return registryrules.ValidateNames(p) == nil
	}
	switch in.Op {
	case agentproto.RegOpList:
		if len(res.Subkeys) > in.MaxSubkeys || len(res.Values) > in.MaxValues {
			return errors.New("it has more subkeys or values than the page asked for")
		}
		if len(res.Matches)+len(res.XKeys) > 0 {
			return errors.New("it holds lines a list does not")
		}
	case agentproto.RegOpValue:
		if len(res.Values) > 1 || len(res.Subkeys) > 0 || len(res.Matches)+len(res.XKeys) > 0 {
			return errors.New("it holds more than the value asked for")
		}
		if len(res.Values) == 1 && in.ValueName != nil && !registryrules.Equal(res.Values[0].Name, *in.ValueName) && res.Values[0].RawName == "" {
			return errors.New("it is for another value")
		}
	case agentproto.RegOpSearch:
		if len(res.Matches) > in.MaxMatches {
			return errors.New("it has more matches than asked for")
		}
		for _, m := range res.Matches {
			if !underAsked(m.Path) {
				return errors.New("a match is outside the key searched")
			}
			switch m.Kind {
			case agentproto.MatchKey, agentproto.MatchValueName, agentproto.MatchData, agentproto.MatchLink:
			default:
				return errors.New("a match is of an unknown kind")
			}
		}
		if len(res.Subkeys)+len(res.Values)+len(res.XKeys) > 0 {
			return errors.New("it holds lines a search does not")
		}
	case agentproto.RegOpExport:
		if len(res.XKeys) > agentproto.RegMaxExportKeys {
			return errors.New("it has more keys than an export may")
		}
		for _, x := range res.XKeys {
			if !underAsked(x.Path) {
				return errors.New("an exported key is outside the key asked for")
			}
		}
		if len(res.Subkeys)+len(res.Values)+len(res.Matches) > 0 {
			return errors.New("it holds lines an export does not")
		}
	}
	return nil
}

func equalPath(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// maskResult drops the data of every value the server's rules mask but the
// agent's did not (an older agent), in place.
func maskResult(res *agentproto.RegistryResult) {
	mask := func(v *agentproto.RegValue) {
		if v.Masked || v.RawName != "" || !registryrules.IsMasked(v.Name, v.Type) {
			return
		}
		*v = agentproto.RegValue{T: v.T, Name: v.Name, Type: v.Type, Size: v.Size, Masked: true}
	}
	for i := range res.Values {
		mask(&res.Values[i])
	}
	for i := range res.XKeys {
		for j := range res.XKeys[i].Values {
			mask(&res.XKeys[i].Values[j])
		}
	}
}

// encodeResultLine writes line i of a decoded result again, in the order
// it had: begin, then the key, subkeys, values, matches, exported keys,
// refused lines and errors, and the end. The order within a kind is kept; the
// order between kinds is the one a reader needs.
func encodeResultLine(res *agentproto.RegistryResult, i int) (json.RawMessage, error) {
	lines := resultOrder(res)
	if i >= len(lines) {
		return nil, errors.New("jobs: a result line is missing")
	}
	return json.Marshal(lines[i])
}

func resultOrder(res *agentproto.RegistryResult) []any {
	out := []any{res.Begin}
	if res.Key != nil {
		out = append(out, *res.Key)
	}
	for _, v := range res.Subkeys {
		out = append(out, v)
	}
	for _, v := range res.Values {
		out = append(out, v)
	}
	for _, v := range res.Matches {
		out = append(out, v)
	}
	for _, v := range res.XKeys {
		out = append(out, v)
	}
	for _, v := range res.Refused {
		out = append(out, v)
	}
	for _, v := range res.Errors {
		out = append(out, v)
	}
	if res.End != nil {
		out = append(out, *res.End)
	}
	return out
}

// purgeStructured empties the inputs and results of finished structured
// jobs once their kind's time has passed, counted from when the job's last
// run ended; no input outlives its results, and none is emptied before them.
func (s *Service) purgeStructured(ctx context.Context, tx pgx.Tx) (int64, error) {
	var n int64
	for _, k := range builtinKinds() {
		keep := k.keepResult(s).Seconds()
		const old = `SELECT j.id FROM jobs j WHERE j.kind = $1
			AND NOT EXISTS (SELECT 1 FROM job_runs r WHERE r.job_id = j.id AND r.status IN ('queued', 'sent', 'running'))
			AND (SELECT max(r.finished_at) FROM job_runs r WHERE r.job_id = j.id) < now() - make_interval(secs => $2)`
		tag, err := tx.Exec(ctx, `UPDATE job_runs SET result = NULL, result_stored_at = NULL, result_removed_at = now()
			WHERE result_stored_at IS NOT NULL AND job_id IN (`+old+`)`, k.Name, keep)
		if err != nil {
			return n, err
		}
		n += tag.RowsAffected()
		if _, err := tx.Exec(ctx, `UPDATE job_inputs SET input = NULL, removed_at = now()
			WHERE removed_at IS NULL AND job_id IN (`+old+`)`, k.Name, keep); err != nil {
			return n, err
		}
		if _, err := tx.Exec(ctx, `UPDATE registry_masked_values SET data = NULL, removed_at = now()
			WHERE removed_at IS NULL AND job_id IN (`+old+`)`, k.Name, keep); err != nil {
			return n, err
		}
		// A job and its runs go after the kind's own time.
		if _, err := tx.Exec(ctx, `DELETE FROM jobs j WHERE j.kind = $1 AND j.created_at < now() - make_interval(secs => $2)
			AND NOT EXISTS (SELECT 1 FROM job_runs r WHERE r.job_id = j.id AND r.status IN ('queued', 'sent', 'running'))`,
			k.Name, k.keepJob(s).Seconds()); err != nil {
			return n, err
		}
	}
	return n, nil
}

// readStructuredInput answers ReadArguments for a structured job: its
// input, to a caller who may read its results. ok is false for a job that is
// not one, which the caller answers as any job's arguments.
func (s *Service) readStructuredInput(ctx context.Context, c access.Caller, id uuid.UUID) (*Arguments, bool, error) {
	var kind *string
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT kind FROM jobs WHERE id = $1`, id).Scan(&kind)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil || kind == nil || !isStructured(*kind) {
		return nil, false, err
	}
	var askerOnly []string
	for _, k := range builtinKinds() {
		if k.AskerOnly {
			askerOnly = append(askerOnly, k.Name)
		}
	}
	read, kindScope := scopeOf(c, rbac.PermJobViewSensitive), scopeOf(c, Kinds[*kind].ReadPerm)
	view := scopeOf(c, rbac.PermJobView)
	st := s.audit.Stamp(c.Actor)
	var result string
	var input []byte
	err = s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		if *kind == KindEventlogQuery {
			// A query for sensitive data is read again only by one who still
			// holds log.view_sensitive (ADR-0068).
			ls := scopeOf(c, rbac.PermLogViewSensitive)
			return tx.QueryRow(ctx, `SELECT result, job_input FROM easyrmm_eventlog_input($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::inet, $17, $18, $19, $20)`,
				id, view.All, view.Orgs, view.Sites, read.All, read.Orgs, read.Sites, kindScope.All, kindScope.Orgs, kindScope.Sites,
				askerOnly, st.At, st.ActorType, st.ActorID, st.ActorLabel, st.SourceIP, st.UserAgent, ls.All, ls.Orgs, ls.Sites).Scan(&result, &input)
		}
		return tx.QueryRow(ctx, `SELECT result, job_input FROM easyrmm_job_input($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::inet, $17)`,
			id, view.All, view.Orgs, view.Sites, read.All, read.Orgs, read.Sites, kindScope.All, kindScope.Orgs, kindScope.Sites,
			askerOnly, st.At, st.ActorType, st.ActorID, st.ActorLabel, st.SourceIP, st.UserAgent).Scan(&result, &input)
	})
	if err != nil {
		return nil, true, err
	}
	if err := readResult(result); err != nil {
		return nil, true, err
	}
	return &Arguments{Args: []string{}, Input: input}, true, nil
}

// RegistryExport is a file built from an export read.
type RegistryExport struct {
	Filename    string
	ContentType string
	Data        []byte
}

// ExportRegistry builds the file of an export read, for the person who
// asked, and records registry.export (format, keys, values, size) in the
// same transaction. An export that did not finish (a bound stopped it) is
// refused: export a smaller key.
func (s *Service) ExportRegistry(ctx context.Context, c access.Caller, id uuid.UUID, format string) (*RegistryExport, error) {
	if format != ExportJSON && format != ExportReg {
		return nil, apperr.Invalid("format", "Use reg or json.")
	}
	var out *RegistryExport
	_, _, err := s.readRegistry(ctx, c, id, "", func(tx pgx.Tx, v *RegistryResultView, res *agentproto.RegistryResult) error {
		switch {
		case res.Begin.Op != agentproto.RegOpExport:
			return apperr.Invalid("format", "This read is not an export.")
		case len(res.Errors) > 0:
			return apperr.Conflict("export_failed", "The export did not read the key: "+res.Errors[0].Message)
		case res.End == nil || !res.End.Complete:
			return apperr.Conflict("export_incomplete", "The export did not finish: export a smaller key.")
		}
		var org, site, device uuid.UUID
		var name string
		if err := tx.QueryRow(ctx, `SELECT r.organization_id, r.site_id, r.device_id, d.name
			FROM job_runs r JOIN devices d ON d.id = r.device_id WHERE r.id = $1`, id).Scan(&org, &site, &device, &name); err != nil {
			return err
		}
		stamp := ""
		if v.ReadAt != nil {
			stamp = v.ReadAt.UTC().Format(time.RFC3339)
		}
		var keys, values int
		switch format {
		case ExportReg:
			data := BuildReg(res)
			keys, values = countExport(res)
			out = &RegistryExport{Filename: exportName(name, res, "reg"), ContentType: "text/plain; charset=utf-16le", Data: data}
		default:
			data, err := BuildJSON(name, stamp, res)
			if err != nil {
				return err
			}
			keys, values = countExport(res)
			out = &RegistryExport{Filename: exportName(name, res, "json"), ContentType: "application/json", Data: data}
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "registry.export", Outcome: audit.Success,
			OrganizationID: org, SiteID: site, DeviceID: device, TargetType: "job_run", TargetID: id.String(),
			Details: map[string]any{"device": name, "format": format, "keys": keys, "values": values, "bytes": len(out.Data),
				"hive": res.Begin.Hive, "view": res.Begin.View},
		})
	})
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, apperr.Conflict("export_unavailable", "There is nothing to export: the read did not return a result.")
	}
	return out, nil
}

// countExport counts the keys and values an export holds.
func countExport(res *agentproto.RegistryResult) (keys, values int) {
	for _, x := range res.XKeys {
		if x.State != agentproto.StateOK {
			continue
		}
		keys++
		for _, v := range x.Values {
			if !v.Masked {
				values++
			}
		}
	}
	return keys, values
}

// exportName is the file's name: the device, the hive and the key's last
// name, with only letters, digits and a few signs.
func exportName(device string, res *agentproto.RegistryResult, ext string) string {
	last := res.Begin.Hive
	if n := len(res.Begin.Path); n > 0 {
		last = res.Begin.Path[n-1]
	}
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
				return r
			}
			return '_'
		}, s)
	}
	return clean(device) + "-" + clean(res.Begin.Hive) + "-" + clean(last) + "." + ext
}
