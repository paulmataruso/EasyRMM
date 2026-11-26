package agentfiles

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Comparison results of a file the device reports.
const (
	StatusMatch = "match"
	// StatusMismatch: the device's hash differs from the build the list
	// holds for its version, or the file is missing.
	StatusMismatch = "mismatch"
	// StatusNotCurrent: MeshAgent updates itself, so a hash that differs
	// from the served build is "not the current build", not a mismatch.
	StatusNotCurrent = "not_current"
	StatusNoExpected = "no_expected"
)

// Expected is the list's value for a reported file.
type Expected struct {
	Source     string    `json:"source"`
	Version    string    `json:"version"`
	MD5        string    `json:"md5"`
	SHA256     string    `json:"sha256"`
	ComputedAt time.Time `json:"computedAt"`
	Stale      bool      `json:"stale"`
}

// FileView is a file a device reported, next to what the list expects.
type FileView struct {
	Program  string    `json:"program"`
	Name     string    `json:"name"`
	Size     int64     `json:"size"`
	MD5      string    `json:"md5"`
	SHA256   string    `json:"sha256"`
	Status   string    `json:"status"`
	Expected *Expected `json:"expected,omitempty"`
}

// Missing is a file the list expects on the device that it did not report.
type Missing struct {
	Program  string   `json:"program"`
	Name     string   `json:"name"`
	Expected Expected `json:"expected"`
}

// InstalledView is a device's installed files, labeled as what they are:
// reported by the device.
type InstalledView struct {
	// Source says so: an agent could report anything.
	Source            string     `json:"source"`
	ObservedAt        *time.Time `json:"observedAt"`
	AgentVersion      string     `json:"agentVersion"`
	MeshAgentVersion  string     `json:"meshAgentVersion,omitempty"`
	PatchAgentVersion string     `json:"patchAgentVersion,omitempty"`
	Files             []FileView `json:"files"`
	Missing           []Missing  `json:"missing"`
	// PatchNote says the EasyPatch agent's files have no expected value
	// until its build publishes a per-file list.
	PatchNote string `json:"patchNote,omitempty"`
}

// DeviceView is what the device page shows of Defender and the hashes.
type DeviceView struct {
	Defender   *agentproto.DefenderReport `json:"defender"`
	DefenderAt *time.Time                 `json:"defenderAt"`
	Installed  *InstalledView             `json:"installed"`
}

// ForDevice returns a device's Defender state and installed files, for
// someone who may view the device.
func (s *Service) ForDevice(ctx context.Context, c access.Caller, id uuid.UUID) (*DeviceView, error) {
	var (
		org, site     uuid.UUID
		arch          string
		def, inst     []byte
		defAt, instAt *time.Time
	)
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT organization_id, site_id, coalesce(agent_arch, ''), defender, defender_at, installed_files, installed_files_at
			FROM devices WHERE id = $1`, id).Scan(&org, &site, &arch, &def, &defAt, &inst, &instAt)
	})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !c.Can(rbac.PermDeviceView, rbac.Site(org, site))) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	v := &DeviceView{DefenderAt: defAt}
	if def != nil {
		v.Defender = &agentproto.DefenderReport{}
		if err := json.Unmarshal(def, v.Defender); err != nil {
			v.Defender = nil
		}
	}
	if inst != nil {
		var f agentproto.InstalledFiles
		if err := json.Unmarshal(inst, &f); err == nil {
			list, err := s.entries(ctx)
			if err != nil {
				return nil, err
			}
			iv := Compare(f, arch, list)
			iv.ObservedAt = instAt
			v.Installed = &iv
		}
	}
	return v, nil
}

// Compare sets what a device reported next to the list. Nothing is acted
// on: a mismatch is shown.
func Compare(f agentproto.InstalledFiles, arch string, list []Entry) InstalledView {
	v := InstalledView{
		Source: "reported by the device", AgentVersion: f.AgentVersion,
		MeshAgentVersion: f.MeshAgentVersion, PatchAgentVersion: f.PatchAgentVersion,
		Files: []FileView{}, Missing: []Missing{},
	}
	agentName := "easyrmm-agent-windows-" + arch + ".exe"
	meshName := "meshagent-windows-" + arch + ".exe"
	find := func(source, name, version string) *Entry {
		var best *Entry
		for i := range list {
			e := &list[i]
			if e.Source == source && e.Name == name && (version == "" || e.Version == version) {
				if best == nil || !e.Stale {
					best = e
				}
			}
		}
		return best
	}
	expected := func(e *Entry) *Expected {
		return &Expected{Source: e.Source, Version: e.Version, MD5: e.MD5, SHA256: e.SHA256, ComputedAt: e.ComputedAt, Stale: e.Stale}
	}
	seen := map[string]bool{}
	for _, x := range f.Files {
		fv := FileView{Program: x.Program, Name: x.Name, Size: x.Size, MD5: x.MD5, SHA256: x.SHA256, Status: StatusNoExpected}
		switch {
		case x.Program == agentproto.InstalledAgent && strings.EqualFold(x.Name, "easyrmm-agent.exe"):
			seen[x.Program] = true
			if e := find(SourceServer, agentName, f.AgentVersion); e != nil {
				fv.Expected = expected(e)
				fv.Status = StatusMismatch
				if e.SHA256 == x.SHA256 {
					fv.Status = StatusMatch
				}
			}
		case x.Program == agentproto.InstalledMeshAgent && strings.EqualFold(x.Name, "meshagent.exe"):
			seen[x.Program] = true
			if e := find(SourceMesh, meshName, ""); e != nil {
				fv.Expected = expected(e)
				fv.Status = StatusNotCurrent
				if e.SHA256 == x.SHA256 {
					fv.Status = StatusMatch
				}
			}
		case x.Program == agentproto.InstalledPatchAgent:
			v.PatchNote = "The files inside the EasyPatch agent's installer are not listed yet, so these have no expected value."
		}
		v.Files = append(v.Files, fv)
	}
	if !seen[agentproto.InstalledAgent] && len(f.Files) > 0 {
		if e := find(SourceServer, agentName, f.AgentVersion); e != nil {
			v.Missing = append(v.Missing, Missing{Program: agentproto.InstalledAgent, Name: "easyrmm-agent.exe", Expected: *expected(e)})
		}
	}
	return v
}
