// Package agentfiles keeps the console's list of every file the server
// hands out or the agents install, with MD5 and SHA-256, and compares what
// each device reports it has installed against it (ADR-0070, part 8). The
// list is read-only; the only way to change it is to change what it
// describes, or to ask for a refresh.
package agentfiles

import (
	"context"
	"crypto/md5" //nolint:gosec // shown for allow lists that ask for MD5; never used to trust anything
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/agents"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/easypatch"
	"github.com/paulmataruso/easyrmm/server/internal/meshcentral"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Sources of the list.
const (
	SourceServer   = "server"
	SourceMesh     = "meshcentral"
	SourcePatching = "patching"
)

// Entry is a line of the list.
type Entry struct {
	ID          uuid.UUID `json:"id"`
	Source      string    `json:"source"`
	Name        string    `json:"name"`
	Platform    string    `json:"platform"`
	Arch        string    `json:"arch"`
	Version     string    `json:"version"`
	Size        int64     `json:"size"`
	MD5         string    `json:"md5"`
	SHA256      string    `json:"sha256"`
	Signer      string    `json:"signer,omitempty"`
	ComputedAt  time.Time `json:"computedAt"`
	Stale       bool      `json:"stale"`
	StaleReason string    `json:"staleReason,omitempty"`
}

// Builds is what the server serves of its own agent.
type Builds interface{ List() []agents.Build }

// Mesh opens the MeshAgent binary MeshCentral serves.
type Mesh interface {
	Binary(ctx context.Context, arch int) (*meshcentral.Download, error)
}

// Patching is the patching engine's agent packages.
type Patching interface {
	PackageList(ctx context.Context) ([]easypatch.AgentPackage, error)
	OpenPackage(ctx context.Context, p easypatch.AgentPackage) (io.ReadCloser, error)
}

// Service keeps the list.
type Service struct {
	db       *database.DB
	log      *slog.Logger
	now      func() time.Time
	builds   Builds
	mesh     Mesh
	patching Patching

	run  sync.Mutex // one refresh at a time
	seen sync.Mutex
	// asked is when a version the list lacked was last looked up.
	asked map[string]time.Time
}

// New returns the service. mesh and patching may be nil.
func New(db *database.DB, log *slog.Logger, b Builds, mesh Mesh, patching Patching) *Service {
	return &Service{db: db, log: log, now: time.Now, builds: b, mesh: mesh, patching: patching, asked: map[string]time.Time{}}
}

// Refresh recomputes the whole list. A source that cannot be read keeps its
// last values, marked stale with the reason, rather than disappearing.
func (s *Service) Refresh(ctx context.Context) error {
	s.run.Lock()
	defer s.run.Unlock()
	return errors.Join(s.refreshServer(ctx), s.refreshMesh(ctx), s.refreshPatching(ctx))
}

// Run refreshes the list now, and again every interval, until ctx ends.
func (s *Service) Run(ctx context.Context, every time.Duration) {
	for {
		if err := s.Refresh(ctx); err != nil {
			s.log.Warn("agent files: refreshing the hash list failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// ServedChanged refreshes the part of the list the server serves itself,
// after a signed build was accepted or removed.
func (s *Service) ServedChanged(ctx context.Context) {
	s.run.Lock()
	defer s.run.Unlock()
	if err := s.refreshServer(ctx); err != nil {
		s.log.Warn("agent files: refreshing the served builds failed", "error", err)
	}
}

// VersionReported is told of an agent version a device reported. When the
// list has no entry for it, the list is computed again, once per version
// every ten minutes.
func (s *Service) VersionReported(version string) {
	var have bool
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_file_hashes WHERE source = $1 AND version = $2)`, SourceServer, version).Scan(&have)
	})
	if err != nil || have {
		return
	}
	s.seen.Lock()
	if t, ok := s.asked[version]; ok && s.now().Sub(t) < 10*time.Minute {
		s.seen.Unlock()
		return
	}
	s.asked[version] = s.now()
	s.seen.Unlock()
	s.ServedChanged(ctx)
}

// row is an entry about to be stored.
type row struct {
	name, platform, arch, version, signer string
	size                                  int64
	md5, sha256                           string
}

func (s *Service) refreshServer(ctx context.Context) error {
	var rows []row
	if s.builds != nil {
		for _, b := range s.builds.List() {
			r := row{name: b.File, platform: b.OS, arch: b.Arch, version: b.Version, size: b.Size, md5: b.MD5, sha256: b.SHA256}
			if b.Signed != nil {
				r.signer = b.Signed.Subject
			}
			rows = append(rows, r)
		}
	}
	return s.replace(ctx, SourceServer, rows)
}

// meshFiles are the MeshAgent binaries the agents' installers use: the
// Windows and Linux ones for the architectures the agent runs on.
var meshFiles = []struct{ goos, arch, name string }{
	{"windows", "amd64", "meshagent-windows-amd64.exe"},
	{"windows", "arm64", "meshagent-windows-arm64.exe"},
	{"linux", "amd64", "meshagent-linux-amd64"},
	{"linux", "arm64", "meshagent-linux-arm64"},
}

func (s *Service) refreshMesh(ctx context.Context) error {
	if s.mesh == nil {
		return nil
	}
	var rows []row
	var errs []error
	for _, f := range meshFiles {
		d, err := s.mesh.Binary(ctx, agentproto.MeshArch(f.goos, f.arch))
		if err == nil {
			var r row
			if r, err = hashStream(d.Body, f.name, f.goos, f.arch, ""); err == nil {
				rows = append(rows, r)
			}
			_ = d.Body.Close()
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f.name, err))
			if serr := s.markStale(ctx, SourceMesh, f.name, "MeshCentral could not be read: "+err.Error()); serr != nil {
				errs = append(errs, serr)
			}
		}
	}
	return errors.Join(append(errs, s.upsert(ctx, SourceMesh, rows, false))...)
}

func (s *Service) refreshPatching(ctx context.Context) error {
	if s.patching == nil {
		return nil
	}
	list, err := s.patching.PackageList(ctx)
	if err != nil {
		return s.markStaleSource(ctx, SourcePatching, "The patching engine could not be read: "+err.Error(), err)
	}
	known, err := s.known(ctx, SourcePatching)
	if err != nil {
		return err
	}
	var rows []row
	var errs []error
	for _, p := range list {
		sha := strings.ToLower(p.SHA256)
		platform := map[string]string{"msi": "windows"}[strings.ToLower(p.Format)]
		if platform == "" {
			platform = "linux"
		}
		r := row{name: p.FileName, platform: platform, arch: strings.ToLower(p.Architecture), version: p.Version, size: p.SizeBytes, sha256: sha}
		// The engine gives SHA-256 only; the package is fetched once for
		// its MD5, and checked against the engine's SHA-256. A package
		// already hashed is not fetched again.
		if k, ok := known[r.key()]; ok && k.sha256 == sha && k.md5 != "" {
			r.md5 = k.md5
		} else if err := s.fetchPackage(ctx, p, &r); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p.FileName, err))
			if serr := s.markStale(ctx, SourcePatching, p.FileName, err.Error()); serr != nil {
				errs = append(errs, serr)
			}
			continue
		}
		rows = append(rows, r)
	}
	return errors.Join(append(errs, s.upsert(ctx, SourcePatching, rows, len(errs) == 0))...)
}

func (r row) key() string { return r.name + "|" + r.version + "|" + r.arch }

func (s *Service) fetchPackage(ctx context.Context, p easypatch.AgentPackage, r *row) error {
	body, err := s.patching.OpenPackage(ctx, p)
	if err != nil {
		return err
	}
	defer func() { _ = body.Close() }()
	got, err := hashStream(body, r.name, r.platform, r.arch, r.version)
	if err != nil {
		return err
	}
	if got.sha256 != r.sha256 {
		return errors.New("the package's SHA-256 is not the one the patching engine lists")
	}
	r.md5, r.size = got.md5, got.size
	return nil
}

// hashStream reads body once and returns both sums.
func hashStream(body io.Reader, name, platform, arch, version string) (row, error) {
	h, m := sha256.New(), md5.New() //nolint:gosec // see the import
	n, err := io.Copy(io.MultiWriter(h, m), io.LimitReader(body, 1<<30))
	if err != nil {
		return row{}, err
	}
	return row{name: name, platform: platform, arch: arch, version: version, size: n,
		md5: hex.EncodeToString(m.Sum(nil)), sha256: hex.EncodeToString(h.Sum(nil))}, nil
}

func (s *Service) known(ctx context.Context, source string) (map[string]row, error) {
	out := map[string]row{}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rs, err := tx.Query(ctx, `SELECT name, version, arch, sha256, md5 FROM agent_file_hashes WHERE source = $1`, source)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var r row
			if err := rs.Scan(&r.name, &r.version, &r.arch, &r.sha256, &r.md5); err != nil {
				return err
			}
			out[r.key()] = r
		}
		return rs.Err()
	})
	return out, err
}

// replace makes a source's rows exactly rows.
func (s *Service) replace(ctx context.Context, source string, rows []row) error {
	return s.upsert(ctx, source, rows, true)
}

// upsert stores rows for a source; with prune it also deletes the source's
// rows that are not among them.
func (s *Service) upsert(ctx context.Context, source string, rows []row, prune bool) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		now := s.now().UTC()
		keys := make([]string, 0, len(rows))
		for _, r := range rows {
			if _, err := tx.Exec(ctx, `INSERT INTO agent_file_hashes (source, name, platform, arch, version, size, md5, sha256, signer, computed_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
				ON CONFLICT (source, name, version, arch) DO UPDATE SET platform = EXCLUDED.platform, size = EXCLUDED.size,
					md5 = EXCLUDED.md5, sha256 = EXCLUDED.sha256, signer = EXCLUDED.signer,
					computed_at = EXCLUDED.computed_at, stale = false, stale_reason = ''`,
				source, r.name, r.platform, r.arch, r.version, r.size, r.md5, r.sha256, r.signer, now); err != nil {
				return err
			}
			keys = append(keys, r.key())
		}
		if !prune {
			return nil
		}
		_, err := tx.Exec(ctx, `DELETE FROM agent_file_hashes WHERE source = $1 AND NOT (name || '|' || version || '|' || arch) = ANY ($2)`, source, keys)
		return err
	})
}

func (s *Service) markStale(ctx context.Context, source, name, reason string) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE agent_file_hashes SET stale = true, stale_reason = left($3, 300) WHERE source = $1 AND name = $2`, source, name, reason)
		return err
	})
}

func (s *Service) markStaleSource(ctx context.Context, source, reason string, cause error) error {
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE agent_file_hashes SET stale = true, stale_reason = left($2, 300) WHERE source = $1`, source, reason)
		return err
	})
	return errors.Join(cause, err)
}

// List returns the list, for anyone who holds org.view somewhere.
func (s *Service) List(ctx context.Context, c access.Caller) ([]Entry, error) {
	if !c.CanAnywhere(rbac.PermOrgView) {
		return nil, apperr.Forbidden()
	}
	return s.entries(ctx)
}

func (s *Service) entries(ctx context.Context) ([]Entry, error) {
	var out []Entry
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		rs, err := tx.Query(ctx, `SELECT id, source, name, platform, arch, version, size, md5, sha256, signer, computed_at, stale, stale_reason
			FROM agent_file_hashes ORDER BY source, platform, name, version DESC, arch`)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var e Entry
			if err := rs.Scan(&e.ID, &e.Source, &e.Name, &e.Platform, &e.Arch, &e.Version, &e.Size, &e.MD5, &e.SHA256, &e.Signer, &e.ComputedAt, &e.Stale, &e.StaleReason); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rs.Err()
	})
	if out == nil {
		out = []Entry{}
	}
	return out, err
}

// RefreshNow recomputes the list when asked from the console: it needs
// settings.manage, as uploading a signed build does.
func (s *Service) RefreshNow(ctx context.Context, c access.Caller) ([]Entry, error) {
	if err := c.RequireGlobal(rbac.PermSettingsManage); err != nil {
		return nil, err
	}
	if err := s.Refresh(ctx); err != nil {
		s.log.Warn("agent files: a refresh asked for in the console did not finish", "error", err)
	}
	return s.entries(ctx)
}
