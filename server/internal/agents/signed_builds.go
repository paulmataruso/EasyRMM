package agents

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // a certificate's thumbprint, as Windows shows it; not for security
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/agents/authenticode"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Signed Windows agent builds (ADR-0049). An operator signs the server's
// Windows builds with their own certificate and tools and uploads them; the
// server checks that each is its own build with only an Authenticode
// signature added, and serves it in place of the release's build of the
// same file name. Coordinated updates then move agents to it, as to any
// other build. EasyRMM never holds the operator's key.

// MaxSignedBuildSize bounds an uploaded build.
const MaxSignedBuildSize = 64 << 20

// SignedBuild is a signed build the server keeps, as the console lists it.
type SignedBuild struct {
	ID      uuid.UUID `json:"id"`
	Arch    string    `json:"arch"`
	Version string    `json:"version"`
	SHA256  string    `json:"sha256"`
	// ReleaseSHA256 is the SHA-256 of the release's build it was made from.
	ReleaseSHA256 string    `json:"releaseSha256"`
	Size          int64     `json:"size"`
	Signer        Signer    `json:"signer"`
	UploadedAt    time.Time `json:"uploadedAt"`
	UploadedBy    string    `json:"uploadedBy,omitempty"`
	// Served says the server hands it out now.
	Served bool `json:"served"`
}

// windowsOS is the platform of the builds Authenticode signs.
const windowsOS = "windows"

// listSigned reads the signed builds kept, newest first, without their
// files.
func listSigned(ctx context.Context, tx pgx.Tx) ([]SignedBuild, error) {
	rows, err := tx.Query(ctx, `SELECT b.id, b.arch, b.version, b.sha256, b.release_sha256, octet_length(b.content),
			b.signer_subject, b.signer_issuer, b.thumbprint, b.not_before, b.not_after, b.timestamped,
			b.uploaded_at, coalesce(u.email, '')
		FROM signed_agent_builds b LEFT JOIN users u ON u.id = b.uploaded_by
		ORDER BY b.uploaded_at DESC, b.arch`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (SignedBuild, error) {
		var b SignedBuild
		err := r.Scan(&b.ID, &b.Arch, &b.Version, &b.SHA256, &b.ReleaseSHA256, &b.Size,
			&b.Signer.Subject, &b.Signer.Issuer, &b.Signer.Thumbprint, &b.Signer.NotBefore, &b.Signer.NotAfter,
			&b.Signer.Timestamped, &b.UploadedAt, &b.UploadedBy)
		return b, err
	})
}

// chooseSigned decides what is served for each Windows release build: the
// signed build made from it; with signedOnly and none, the newest signed
// build for its architecture, or nothing (withheld). Others serve the
// release's build. signed is newest first.
func chooseSigned(release []Build, signed []SignedBuild, signedOnly bool) (served map[string]SignedBuild, withheld map[string]bool) {
	served, withheld = map[string]SignedBuild{}, map[string]bool{}
	for _, it := range release {
		if it.OS != windowsOS {
			continue
		}
		i := slices.IndexFunc(signed, func(b SignedBuild) bool { return b.Arch == it.Arch && b.ReleaseSHA256 == it.SHA256 })
		if i < 0 && signedOnly {
			i = slices.IndexFunc(signed, func(b SignedBuild) bool { return b.Arch == it.Arch })
			if i < 0 {
				withheld[it.File] = true
				continue
			}
		}
		if i >= 0 {
			served[it.File] = signed[i]
		}
	}
	return served, withheld
}

// LoadSignedBuilds has the server serve the signed builds it keeps, as the
// update setting says. It runs at startup and after every change.
func (s *Service) LoadSignedBuilds(ctx context.Context) error {
	if s.builds == nil {
		return nil
	}
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		p, err := loadPolicy(ctx, tx)
		if err != nil {
			return err
		}
		kept, err := listSigned(ctx, tx)
		if err != nil {
			return err
		}
		choice, withheld := chooseSigned(s.builds.Release(), kept, p.SignedOnly)
		served := make(map[string]signedContent, len(choice))
		for file, b := range choice {
			var content []byte
			if err := tx.QueryRow(ctx, `SELECT content FROM signed_agent_builds WHERE id = $1`, b.ID).Scan(&content); err != nil {
				return err
			}
			if sum := sha256.Sum256(content); hex.EncodeToString(sum[:]) != b.SHA256 {
				return fmt.Errorf("the signed build %s for %s does not match its SHA-256", b.Version, b.Arch)
			}
			signer := b.Signer
			served[file] = signedContent{content: content, older: !releaseOf(s.builds, file, b.ReleaseSHA256), build: Build{
				OS: windowsOS, Arch: b.Arch, File: file, Size: int64(len(content)), SHA256: b.SHA256,
				Version: b.Version, Signed: &signer, modTime: b.UploadedAt,
			}}
		}
		s.builds.serve(served, withheld)
		return nil
	})
	if err != nil {
		return fmt.Errorf("agents: loading the signed builds: %w", err)
	}
	return nil
}

// releaseOf says whether the release's build with a file name has a
// SHA-256.
func releaseOf(b *Builds, file, sha string) bool {
	return slices.ContainsFunc(b.Release(), func(it Build) bool { return it.File == file && it.SHA256 == sha })
}

// UploadSignedBuild checks a signed Windows build and keeps it: the server
// serves it in place of the release's build it was made from. A build of
// the same architecture and version is replaced; of the others, only the
// newest stays.
func (s *Service) UploadSignedBuild(ctx context.Context, c access.Caller, data []byte) (*SignedBuild, error) {
	if err := c.RequireGlobal(rbac.PermSettingsManage); err != nil {
		return nil, err
	}
	if s.builds == nil || !slices.ContainsFunc(s.builds.Release(), func(b Build) bool { return b.OS == windowsOS }) {
		return nil, apperr.Conflict("no_windows_build", "This server has no Windows agent builds to sign.")
	}
	if len(data) > MaxSignedBuildSize {
		return nil, apperr.Invalid("file", fmt.Sprintf("The file is larger than %d MiB.", MaxSignedBuildSize>>20))
	}
	// The reader's errors say what is wrong with the file, for whoever
	// uploaded it.
	sig, err := authenticode.Verify(data)
	if err != nil {
		return nil, apperr.Invalid("file", sentence(err))
	}
	release, err := s.signedFrom(data, sig)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	thumb := sha1.Sum(sig.Signer.Raw) //nolint:gosec // see the import
	out := &SignedBuild{
		ID: uuid.New(), Arch: release.Arch, Version: release.Version, SHA256: hex.EncodeToString(sum[:]),
		ReleaseSHA256: release.SHA256, Size: int64(len(data)),
		Signer: Signer{
			Subject: clean(sig.Signer.Subject.String(), 1000), Issuer: clean(sig.Signer.Issuer.String(), 1000),
			Thumbprint: hex.EncodeToString(thumb[:]), NotBefore: sig.Signer.NotBefore, NotAfter: sig.Signer.NotAfter,
			Timestamped: sig.Timestamped,
		},
		UploadedBy: c.Actor.Label,
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var replaced bool
		if err := tx.QueryRow(ctx, `WITH gone AS (DELETE FROM signed_agent_builds WHERE arch = $1 AND version = $2 RETURNING 1)
			SELECT EXISTS (SELECT 1 FROM gone)`, out.Arch, out.Version).Scan(&replaced); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO signed_agent_builds (id, arch, version, sha256, release_sha256, content,
				signer_subject, signer_issuer, thumbprint, not_before, not_after, timestamped, uploaded_at, uploaded_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING uploaded_at`,
			out.ID, out.Arch, out.Version, out.SHA256, out.ReleaseSHA256, data, out.Signer.Subject, out.Signer.Issuer,
			out.Signer.Thumbprint, out.Signer.NotBefore, out.Signer.NotAfter, out.Signer.Timestamped, s.now(), userID(c),
		).Scan(&out.UploadedAt); err != nil {
			return err
		}
		// Of the builds of other versions, the newest stays: what "Only
		// signed builds" serves until this version's is uploaded, after the
		// next upgrade.
		if _, err := tx.Exec(ctx, `DELETE FROM signed_agent_builds WHERE arch = $1 AND version <> $2 AND id <> ALL (
				SELECT id FROM signed_agent_builds WHERE arch = $1 AND version <> $2 ORDER BY uploaded_at DESC LIMIT 1)`,
			out.Arch, out.Version); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "agent_updates.signed_upload", Outcome: audit.Success,
			TargetType: "signed_agent_build", TargetID: out.ID.String(),
			Details: map[string]any{
				"arch": out.Arch, "version": out.Version, "sha256": out.SHA256, "signer": out.Signer.Subject,
				"thumbprint": out.Signer.Thumbprint, "timestamped": out.Signer.Timestamped, "replaced": replaced,
			},
		})
	})
	if err != nil {
		return nil, err
	}
	if err := s.LoadSignedBuilds(ctx); err != nil {
		return nil, err
	}
	out.Served = s.served(out.SHA256)
	return out, nil
}

// signedFrom finds the release's Windows build that data is, with only a
// signature added: the one with the same Authenticode digest.
func (s *Service) signedFrom(data []byte, sig *authenticode.Signature) (Build, error) {
	var files []string
	for _, b := range s.builds.Release() {
		if b.OS != windowsOS {
			continue
		}
		files = append(files, b.File)
		release, err := s.builds.readRelease(b.File)
		if err != nil {
			return Build{}, fmt.Errorf("agents: reading %s: %w", b.File, err)
		}
		d, err := authenticode.Digest(release, sig.Hash)
		if err != nil {
			return Build{}, fmt.Errorf("agents: the digest of %s: %w", b.File, err)
		}
		if bytes.Equal(d, sig.Digest) {
			return b, nil
		}
	}
	v := s.builds.Version()
	if v == "" {
		v = "unknown"
	}
	return Build{}, apperr.Invalid("file", fmt.Sprintf("This is not one of this server's Windows agent builds (%s, version %s) with a signature added. "+
		"Sign those files without changing them otherwise.", strings.Join(files, ", "), v))
}

// ReleaseBuild opens the release's Windows build with a file name, for an
// operator to sign.
func (s *Service) ReleaseBuild(_ context.Context, c access.Caller, file string) (*os.File, Build, error) {
	if err := c.RequireGlobal(rbac.PermSettingsManage); err != nil {
		return nil, Build{}, err
	}
	if s.builds == nil || !slices.ContainsFunc(s.builds.Release(), func(b Build) bool { return b.File == file && b.OS == windowsOS }) {
		return nil, Build{}, apperr.NotFound()
	}
	return s.builds.OpenRelease(file)
}

// served says whether the build with a SHA-256 is served now.
func (s *Service) served(sha string) bool {
	return slices.ContainsFunc(s.builds.List(), func(b Build) bool { return b.SHA256 == sha })
}

// RemoveSignedBuild deletes a signed build. The release's build is served
// again in its place, unless only signed builds are served.
func (s *Service) RemoveSignedBuild(ctx context.Context, c access.Caller, id uuid.UUID) error {
	if err := c.RequireGlobal(rbac.PermSettingsManage); err != nil {
		return err
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var arch, version, sha, subject, thumbprint string
		err := tx.QueryRow(ctx, `DELETE FROM signed_agent_builds WHERE id = $1
			RETURNING arch, version, sha256, signer_subject, thumbprint`, id).Scan(&arch, &version, &sha, &subject, &thumbprint)
		if errors.Is(err, pgx.ErrNoRows) {
			return apperr.NotFound()
		}
		if err != nil {
			return err
		}
		p, err := loadPolicy(ctx, tx)
		if err != nil {
			return err
		}
		if p.SignedOnly {
			var left bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM signed_agent_builds)`).Scan(&left); err != nil {
				return err
			}
			if !left {
				return apperr.Conflict("last_signed_build",
					"Only signed builds are handed out, and this is the last one: no Windows agent could be installed. Hand out the release's build first.")
			}
		}
		return s.audit.Write(ctx, tx, audit.Event{
			Actor: c.Actor, Action: "agent_updates.signed_remove", Outcome: audit.Success,
			TargetType: "signed_agent_build", TargetID: id.String(),
			Details: map[string]any{"arch": arch, "version": version, "sha256": sha, "signer": subject, "thumbprint": thumbprint},
		})
	})
	if err != nil {
		return err
	}
	return s.LoadSignedBuilds(ctx)
}

// sentence makes an error's text a sentence: capitalized, with a full stop.
func sentence(err error) string {
	m := err.Error()
	m = strings.ToUpper(m[:1]) + m[1:]
	if !strings.HasSuffix(m, ".") {
		m += "."
	}
	return m
}
