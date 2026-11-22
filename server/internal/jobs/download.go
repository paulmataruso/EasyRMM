package jobs

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/reports"
)

// Downloads of a job's output and results (ADR-0064, "Downloads and
// results"). Output goes through the same audited reads as the console's
// page (ADR-0063), each read recorded with what was downloaded; the results
// carry no output and are recorded as an export.

// What a run's output endpoint downloads.
const (
	DownloadStdout = "stdout"
	DownloadStderr = "stderr"
	DownloadJSON   = "json"
)

// File is a download: its name and its content.
type File struct {
	Name string
	Body []byte
}

// RunResult is a run as downloads describe it: where it ran, what ran, and
// how it ended. Everyone with job.view sees all of it.
type RunResult struct {
	RunID          uuid.UUID  `json:"runId"`
	JobID          uuid.UUID  `json:"jobId"`
	Device         string     `json:"device"`
	DeviceID       uuid.UUID  `json:"deviceId"`
	Organization   string     `json:"organization"`
	OrganizationID uuid.UUID  `json:"organizationId"`
	Site           string     `json:"site"`
	SiteID         uuid.UUID  `json:"siteId"`
	Kind           string     `json:"kind"`
	ScriptName     string     `json:"scriptName"`
	SHA256         string     `json:"sha256"`
	Shell          string     `json:"shell"`
	StartedBy      string     `json:"startedBy"`
	Status         string     `json:"status"`
	ExitCode       *int       `json:"exitCode"`
	Error          string     `json:"error"`
	QueuedAt       time.Time  `json:"queuedAt"`
	DeliveredAt    *time.Time `json:"deliveredAt"`
	StartedAt      *time.Time `json:"startedAt"`
	FinishedAt     *time.Time `json:"finishedAt"`
}

// RunDownload is a run with its output, as ?download=json and each run's
// result.json in a job's archive have it.
type RunDownload struct {
	RunResult
	Output
}

// resultColumns are a run's columns for downloads: runColumns and the job's.
const resultColumns = runColumns + `, j.kind, encode(j.body_sha256, 'hex'), j.shell, j.created_by_label`

func scanResult(row pgx.Row) (*RunResult, error) {
	var x RunResult
	r, err := scanRun(row, &x.Kind, &x.SHA256, &x.Shell, &x.StartedBy)
	if err != nil {
		return nil, err
	}
	x.RunID, x.JobID, x.Device, x.DeviceID = r.ID, r.JobID, r.DeviceName, r.DeviceID
	x.Organization, x.OrganizationID, x.Site, x.SiteID = r.OrganizationName, r.OrganizationID, r.SiteName, r.SiteID
	x.ScriptName, x.Status, x.ExitCode, x.Error = r.ScriptName, r.Status, r.ExitCode, r.Error
	x.QueuedAt, x.DeliveredAt, x.StartedAt, x.FinishedAt = r.CreatedAt, r.SentAt, r.StartedAt, r.FinishedAt
	return &x, nil
}

func (r *RunResult) open() bool {
	return r.Status == StatusQueued || r.Status == StatusSent || r.Status == StatusRunning
}

// DownloadOutput returns a finished run's output as a file to a caller who
// holds job.view_sensitive at its site: one stream as text (stdout or
// stderr), or the run with both streams as JSON. The read is recorded as
// job_run.output_view with what was downloaded, in the transaction that
// reads it, as ReadOutput's is; a run that printed nothing gives empty
// streams and is not recorded.
func (s *Service) DownloadOutput(ctx context.Context, c access.Caller, id uuid.UUID, what string) (*File, error) {
	switch what {
	case DownloadStdout, DownloadStderr, DownloadJSON:
	default:
		return nil, apperr.Invalid("download", "Download stdout, stderr or json.")
	}
	var res *RunResult
	out, err := s.readOutput(ctx, c, id, what, func(tx pgx.Tx) error {
		var err error
		res, err = scanResult(tx.QueryRow(ctx, `SELECT `+resultColumns+runFrom+` WHERE r.id = $1`, id))
		return err
	})
	if err != nil {
		return nil, err
	}
	base := fileName(res.Device) + "_" + res.RunID.String()
	switch what {
	case DownloadStdout:
		return &File{Name: base + "_stdout.txt", Body: []byte(out.Stdout)}, nil
	case DownloadStderr:
		return &File{Name: base + "_stderr.txt", Body: []byte(out.Stderr)}, nil
	}
	b, err := runJSON(res, out)
	if err != nil {
		return nil, err
	}
	return &File{Name: base + ".json", Body: b}, nil
}

func runJSON(res *RunResult, out *Output) ([]byte, error) {
	b, err := json.MarshalIndent(RunDownload{RunResult: *res, Output: *out}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// fileName makes a name safe in a file or archive name: letters, digits,
// '-', '_' and '.', never starting with a dot nor holding two together, at
// most 64 characters.
func fileName(s string) string {
	var b strings.Builder
	last := rune(0)
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.' && last != '.':
			b.WriteRune(r)
		default:
			r = '_'
			b.WriteRune(r)
		}
		last = r
		if b.Len() >= 64 {
			break
		}
	}
	name := strings.TrimLeft(b.String(), ".")
	if name == "" {
		return "device"
	}
	return name
}

// visibleResults reads the job's runs the caller sees, by device name, and
// the job itself; not found when the caller sees none.
func (s *Service) visibleResults(ctx context.Context, tx pgx.Tx, c access.Caller, id uuid.UUID) ([]*RunResult, error) {
	rows, err := tx.Query(ctx, `SELECT `+resultColumns+runFrom+` WHERE r.job_id = $1 ORDER BY lower(d.name), r.id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*RunResult
	for rows.Next() {
		r, err := scanResult(rows)
		if err != nil {
			return nil, err
		}
		if c.Can(rbac.PermJobView, rbac.Site(r.OrganizationID, r.SiteID)) {
			out = append(out, r)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, apperr.NotFound()
	}
	return out, nil
}

// resultsColumns are the columns of a job's results, without output.
var resultsColumns = []reports.Column{
	{Key: "device", Label: "Device", Type: reports.TypeText},
	{Key: "organization", Label: "Organization", Type: reports.TypeText},
	{Key: "site", Label: "Site", Type: reports.TypeText},
	{Key: "status", Label: "Status", Type: reports.TypeText},
	{Key: "exitCode", Label: "Exit code", Type: reports.TypeNumber},
	{Key: "error", Label: "Error", Type: reports.TypeText},
	{Key: "queued", Label: "Queued", Type: reports.TypeTime},
	{Key: "started", Label: "Started", Type: reports.TypeTime},
	{Key: "finished", Label: "Finished", Type: reports.TypeTime},
	{Key: "run", Label: "Run", Type: reports.TypeText},
}

// statusLabels name run statuses as the console does.
var statusLabels = map[string]string{
	StatusQueued: "Queued", StatusSent: "Delivered", StatusRunning: "Running", StatusSucceeded: "Succeeded",
	StatusFailed: "Failed", StatusTimedOut: "Timed out", StatusCanceled: "Canceled", StatusExpired: "Expired", StatusLost: "No result",
}

func resultRow(r *RunResult) []any {
	var exit any
	if r.ExitCode != nil {
		exit = *r.ExitCode
	}
	return []any{r.Device, r.Organization, r.Site, statusLabels[r.Status], exit, r.Error, r.QueuedAt, timeOrNil(r.StartedAt),
		timeOrNil(r.FinishedAt), r.RunID.String()}
}

func timeOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

// ResultsCSV returns a job's results as CSV, one row per run the caller
// sees: the device, where it is, the status, exit code, error and times,
// never output. It is an export (ADR-0029): recorded as job.results_export
// once for each organization whose runs it holds, under the site when
// those runs share one, in the transaction that reads them; nothing is
// returned if the record cannot be written.
func (s *Service) ResultsCSV(ctx context.Context, c access.Caller, id uuid.UUID) (*File, error) {
	var runs []*RunResult
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		var err error
		if runs, err = s.visibleResults(ctx, tx, c, id); err != nil {
			return err
		}
		return s.recordByOrganization(ctx, tx, c, runs, func(org, site uuid.UUID, n int) audit.Event {
			return audit.Event{Actor: c.Actor, Action: "job.results_export", Outcome: audit.Success,
				OrganizationID: org, SiteID: site, TargetType: "job", TargetID: id.String(),
				Details: map[string]any{"jobId": id.String(), "script": runs[0].ScriptName, "kind": runs[0].Kind, "rows": n}}
		})
	})
	if err != nil {
		return nil, err
	}
	rep := &reports.Report{Columns: resultsColumns}
	for _, r := range runs {
		rep.Rows = append(rep.Rows, resultRow(r))
	}
	var buf bytes.Buffer
	if err := reports.WriteCSV(&buf, rep); err != nil {
		return nil, err
	}
	return &File{Name: fileName(runs[0].ScriptName) + "_" + id.String() + "_results.csv", Body: buf.Bytes()}, nil
}

// recordByOrganization writes one record for each organization of the
// runs, under the site when that organization's runs share one, with the
// number of runs.
func (s *Service) recordByOrganization(ctx context.Context, tx pgx.Tx, c access.Caller, runs []*RunResult,
	event func(org, site uuid.UUID, n int) audit.Event) error {
	type group struct {
		n     int
		sites map[uuid.UUID]bool
	}
	groups := map[uuid.UUID]*group{}
	for _, r := range runs {
		g := groups[r.OrganizationID]
		if g == nil {
			g = &group{sites: map[uuid.UUID]bool{}}
			groups[r.OrganizationID] = g
		}
		g.n++
		g.sites[r.SiteID] = true
	}
	for _, org := range slices.SortedFunc(maps.Keys(groups), func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) }) {
		g := groups[org]
		var site uuid.UUID
		if len(g.sites) == 1 {
			for site = range g.sites {
			}
		}
		if err := s.audit.Write(ctx, tx, event(org, site, g.n)); err != nil {
			return err
		}
	}
	return nil
}

// OutputArchive is a job's output as a ZIP archive whose reads are already
// recorded: OutputArchive records them and Write sends them.
type OutputArchive struct {
	// Name is the archive's file name.
	Name string

	s *Service
	c access.Caller
	// runs are every run of the job the caller sees.
	runs []*RunResult
	// readable are the runs at sites where the caller holds
	// job.view_sensitive.
	readable map[uuid.UUID]bool
	// included are the runs whose output goes in the archive, each with
	// the id of its record, or 0 for a run that printed nothing.
	included map[uuid.UUID]int64
}

// OutputArchive prepares a job's output for download as a ZIP archive: for
// each finished run whose output the caller may read, a folder with
// stdout.txt, stderr.txt and result.json, and runs.csv saying for every run
// they see whether its output is included or why not. The transaction that
// chooses those runs records each one's read as job_run.output_view with
// download zip, and commits before anything is sent; if it cannot, nothing
// is. A caller who sees runs of the job and may read none of them is
// refused, recorded as denied within ADR-0063's bound.
func (s *Service) OutputArchive(ctx context.Context, c access.Caller, id uuid.UUID) (*OutputArchive, error) {
	view, read := scopeOf(c, rbac.PermJobView), scopeOf(c, rbac.PermJobViewSensitive)
	st := s.audit.Stamp(c.Actor)
	a := &OutputArchive{s: s, c: c, readable: map[uuid.UUID]bool{}, included: map[uuid.UUID]int64{}}
	result := "ok"
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT result, run_id, record_id
			FROM easyrmm_job_output_zip($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::inet, $13)`,
			id, view.All, view.Orgs, view.Sites, read.All, read.Orgs, read.Sites,
			st.At, st.ActorType, st.ActorID, st.ActorLabel, st.SourceIP, st.UserAgent)
		if err != nil {
			return err
		}
		for rows.Next() {
			var run *uuid.UUID
			var record *int64
			if err := rows.Scan(&result, &run, &record); err != nil {
				rows.Close()
				return err
			}
			if run != nil {
				a.included[*run] = 0
				if record != nil {
					a.included[*run] = *record
				}
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil || result != "ok" {
			// A refusal's record commits with the transaction.
			return err
		}
		a.runs, err = s.visibleResults(ctx, tx, c, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := readResult(result); err != nil {
		return nil, err
	}
	for _, r := range a.runs {
		a.readable[r.RunID] = c.Can(rbac.PermJobViewSensitive, rbac.Site(r.OrganizationID, r.SiteID))
	}
	a.Name = fileName(a.runs[0].ScriptName) + "_" + id.String() + "_output.zip"
	return a, nil
}

// errRecordedRemoved is a run whose output was removed after its read was
// recorded.
var errRecordedRemoved = errors.New("jobs: the output was removed after its read was recorded")

// recordedOutput reads one run's output for the archive, in a transaction
// of its own, against the record of its read.
func (s *Service) recordedOutput(ctx context.Context, c access.Caller, run uuid.UUID, record int64) (*Output, error) {
	view, read := scopeOf(c, rbac.PermJobView), scopeOf(c, rbac.PermJobViewSensitive)
	var result string
	var stdout, stderr *string
	var outCut, errCut *bool
	err := s.db.InTx(ctx, c.Scope, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT result, out_text, err_text, out_cut, err_cut
			FROM easyrmm_job_run_output_recorded($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			run, record, nullUUID(c.Actor.ID), s.audit.Stamp(c.Actor).At, view.All, view.Orgs, view.Sites, read.All, read.Orgs, read.Sites).
			Scan(&result, &stdout, &stderr, &outCut, &errCut)
	})
	switch {
	case err != nil:
		return nil, err
	case result == "output_removed":
		return nil, errRecordedRemoved
	case result != "ok":
		return nil, readResult(result)
	}
	return &Output{Stdout: *stdout, Stderr: *stderr, StdoutTruncated: *outCut, StderrTruncated: *errCut}, nil
}

// Why a run's output is or is not in the archive, as runs.csv says it.
const (
	archiveIncluded = "Included"
	archiveEmpty    = "Included: nothing was written"
	archiveHidden   = "Hidden: needs permission to see job output"
	archiveRemoved  = "Removed"
	archiveOpen     = "Not finished"
)

// Write writes the archive to w. Each run's output is read in a short
// transaction of its own, closed before its files are written, so a slow
// client holds no database connection. A run whose output was removed
// after its record is listed as removed in runs.csv, without its files.
func (a *OutputArchive) Write(ctx context.Context, w io.Writer) error {
	zw := zip.NewWriter(w)
	now := time.Now().UTC()
	state := map[uuid.UUID]string{}
	for _, r := range a.runs {
		record, ok := a.included[r.RunID]
		switch {
		case !a.readable[r.RunID]:
			state[r.RunID] = archiveHidden
			continue
		case r.open():
			state[r.RunID] = archiveOpen
			continue
		case !ok:
			state[r.RunID] = archiveRemoved
			continue
		}
		out := &Output{}
		state[r.RunID] = archiveEmpty
		if record != 0 {
			var err error
			out, err = a.s.recordedOutput(ctx, a.c, r.RunID, record)
			switch {
			case errors.Is(err, errRecordedRemoved):
				state[r.RunID] = archiveRemoved
				continue
			case errors.Is(err, apperr.ErrNotFound), errors.Is(err, apperr.ErrForbidden):
				state[r.RunID] = archiveHidden
				continue
			case err != nil:
				return err
			}
			state[r.RunID] = archiveIncluded
		}
		res, err := runJSON(r, out)
		if err != nil {
			return err
		}
		dir := fileName(r.Device) + "_" + r.RunID.String() + "/"
		for _, f := range []File{{Name: dir + "stdout.txt", Body: []byte(out.Stdout)}, {Name: dir + "stderr.txt", Body: []byte(out.Stderr)},
			{Name: dir + "result.json", Body: res}} {
			if err := addFile(zw, f, now); err != nil {
				return err
			}
		}
	}
	rep := &reports.Report{Columns: append(slices.Clone(resultsColumns), reports.Column{Key: "output", Label: "Output", Type: reports.TypeText},
		reports.Column{Key: "folder", Label: "Folder", Type: reports.TypeText})}
	for _, r := range a.runs {
		folder := ""
		if st := state[r.RunID]; st == archiveIncluded || st == archiveEmpty {
			folder = fileName(r.Device) + "_" + r.RunID.String()
		}
		rep.Rows = append(rep.Rows, append(resultRow(r), state[r.RunID], folder))
	}
	var csv bytes.Buffer
	if err := reports.WriteCSV(&csv, rep); err != nil {
		return err
	}
	if err := addFile(zw, File{Name: "runs.csv", Body: csv.Bytes()}, now); err != nil {
		return err
	}
	return zw.Close()
}

func addFile(zw *zip.Writer, f File, at time.Time) error {
	w, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: zip.Deflate, Modified: at})
	if err != nil {
		return fmt.Errorf("jobs: archive entry %s: %w", f.Name, err)
	}
	_, err = w.Write(f.Body)
	return err
}
