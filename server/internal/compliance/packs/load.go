package packs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/content"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/library"
	"github.com/paulmataruso/easyrmm/server/internal/database"
)

// Load states of a pack.
const (
	StateLoaded    = "loaded"
	StateUnchanged = "unchanged"
	StateRefused   = "refused"
)

// Status is what the loader did with one content file.
type Status struct {
	Path    string `json:"path"`
	Key     string `json:"key"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
	State   string `json:"state"`
	Reason  string `json:"reason,omitempty"`
}

// Load reads the content tree into the global tables (ADR-0078, section 6,
// lifecycle step 1). It verifies each file's hash against the manifest and
// the manifest's signature, checks every file's class against the edition
// and validates it. A failure stops that file, not the server: the file is
// reported refused with its reason. Controls the library already holds keep
// their version: a changed definition under an old version is refused.
func Load(ctx context.Context, db *database.DB, fsys fs.FS, edition string, log *slog.Logger) ([]Status, error) {
	if err := content.VerifySignature(fsys, edition, content.ReleasePublicKey); err != nil {
		return nil, err
	}
	m, err := content.ReadManifest(fsys)
	if err != nil {
		return nil, err
	}
	srcs, err := content.ReadSources(fsys)
	if err != nil {
		return nil, err
	}
	srcClass := map[string]compliance.Class{}
	for _, s := range srcs {
		srcClass[s.ID] = s.LicenceClass
	}
	var out []Status
	refuse := func(e content.Entry, key, version, reason string) {
		log.Warn("compliance: content refused", "path", e.Path, "reason", reason)
		out = append(out, Status{Path: e.Path, Key: key, Version: version, Kind: e.Kind, State: StateRefused, Reason: reason})
	}

	// The library first: every pack's mappings name its controls.
	type libFile struct {
		e content.Entry
		f library.File
	}
	var libs []libFile
	var all []library.File
	for _, e := range m.Files {
		if e.Kind != content.KindLibrary {
			continue
		}
		b, err := fs.ReadFile(fsys, e.Path)
		if err != nil {
			return nil, err
		}
		f, err := library.Parse(b)
		if err == nil {
			err = firstErr(checkFile(e, b, edition), classErr(e, f.Library.LicenceClass), errs(library.Validate(f)))
		}
		if err != nil {
			refuse(e, f.Library.Key, f.Library.Version, err.Error())
			continue
		}
		libs = append(libs, libFile{e, f})
		all = append(all, f)
	}
	idx, err := library.Build(all...)
	if err != nil {
		return nil, err
	}
	type packFile struct {
		e content.Entry
		f File
	}
	var pfs []packFile
	for _, e := range m.Files {
		if e.Kind != content.KindPack {
			continue
		}
		b, err := fs.ReadFile(fsys, e.Path)
		if err != nil {
			return nil, err
		}
		f, err := Parse(b)
		if err == nil {
			err = firstErr(checkFile(e, b, edition), classErr(e, f.Pack.LicenceClass), errs(Validate(f, idx, srcClass, edition)))
		}
		if err != nil {
			refuse(e, f.Pack.Key, f.Pack.Version, err.Error())
			continue
		}
		pfs = append(pfs, packFile{e, f})
	}

	err = db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		for _, s := range srcs {
			if !compliance.Allowed(edition, s.LicenceClass, s.ReviewState, s.ReviewRef) {
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO compliance_sources (id, title, publisher, url, licence_class, licence_spdx,
					licence_note, attribution, retrieved_at, sha256, review_state, review_ref)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::date, $10, $11, NULLIF($12, ''))
				ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, publisher = EXCLUDED.publisher, url = EXCLUDED.url,
					licence_class = EXCLUDED.licence_class, licence_spdx = EXCLUDED.licence_spdx, licence_note = EXCLUDED.licence_note,
					attribution = EXCLUDED.attribution, retrieved_at = EXCLUDED.retrieved_at, sha256 = EXCLUDED.sha256,
					review_state = EXCLUDED.review_state, review_ref = EXCLUDED.review_ref`,
				s.ID, s.Title, s.Publisher, s.URL, string(s.LicenceClass), s.LicenceSPDX, s.LicenceNote, s.Attribution,
				s.RetrievedAt, s.SHA256, s.ReviewState, s.ReviewRef); err != nil {
				return fmt.Errorf("source %s: %w", s.ID, err)
			}
		}
		for _, l := range libs {
			st, err := storeLibrary(ctx, tx, l.e, l.f)
			if err != nil {
				return err
			}
			out = append(out, st)
		}
		for _, p := range pfs {
			st, err := storePack(ctx, tx, p.e, p.f)
			if err != nil {
				return err
			}
			out = append(out, st)
		}
		return nil
	})
	if err != nil {
		// A control whose definition changed under its version refuses the library, which
		// the caller logs; nothing was written.
		return out, err
	}
	return out, nil
}

func checkFile(e content.Entry, b []byte, edition string) error {
	if content.Sum(b) != e.SHA256 {
		return errors.New("its SHA-256 does not match the manifest")
	}
	if !compliance.Allowed(edition, e.LicenceClass, e.ReviewState, e.ReviewRef) {
		if e.ReviewState == compliance.ReviewNeeded {
			return fmt.Errorf("review is still needed before a %s build may carry it", edition)
		}
		return fmt.Errorf("licence class %s is not allowed in a %s build", e.LicenceClass, edition)
	}
	return nil
}

// classErr refuses a file whose own class differs from the manifest's.
func classErr(e content.Entry, declared compliance.Class) error {
	if e.LicenceClass != declared {
		return fmt.Errorf("the manifest says class %s, the file says %s", e.LicenceClass, declared)
	}
	return nil
}

func errs(l []error) error { return errors.Join(l...) }

func firstErr(l ...error) error {
	for _, e := range l {
		if e != nil {
			return e
		}
	}
	return nil
}

func storeLibrary(ctx context.Context, tx pgx.Tx, e content.Entry, f library.File) (Status, error) {
	st := Status{Path: e.Path, Key: f.Library.Key, Version: f.Library.Version, Kind: "library", State: StateLoaded}
	var id string
	var oldHash string
	err := tx.QueryRow(ctx, `SELECT id::text, manifest_sha256 FROM compliance_packs WHERE key = $1 AND origin = 'builtin'`, f.Library.Key).Scan(&id, &oldHash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		err = tx.QueryRow(ctx, `INSERT INTO compliance_packs (key, version, kind, title, origin, licence_class, source_id, review_state, manifest_sha256)
			VALUES ($1, $2, 'library', $3, 'builtin', $4, $5, $6, $7) RETURNING id::text`,
			f.Library.Key, f.Library.Version, f.Library.Title, string(f.Library.LicenceClass), f.Library.SourceID, f.Library.ReviewState, e.SHA256).Scan(&id)
		if err != nil {
			return st, err
		}
	case err != nil:
		return st, err
	case oldHash == e.SHA256:
		st.State = StateUnchanged
		return st, nil
	default:
		if _, err := tx.Exec(ctx, `UPDATE compliance_packs SET version = $2, title = $3, licence_class = $4, source_id = $5,
				review_state = $6, manifest_sha256 = $7 WHERE id = $1::uuid`,
			id, f.Library.Version, f.Library.Title, string(f.Library.LicenceClass), f.Library.SourceID, f.Library.ReviewState, e.SHA256); err != nil {
			return st, err
		}
	}
	for _, c := range f.Controls {
		body, err := json.Marshal(c)
		if err != nil {
			return st, err
		}
		sum := content.Sum(body)
		var have string
		err = tx.QueryRow(ctx, `SELECT body_sha256 FROM compliance_controls WHERE id = $1 AND version = $2`, c.ID, c.Version).Scan(&have)
		switch {
		case err == nil && have != sum:
			return st, fmt.Errorf("control %s version %d changed without a version bump", c.ID, c.Version)
		case err == nil:
			if _, err := tx.Exec(ctx, `UPDATE compliance_controls SET pack_id = $3::uuid WHERE id = $1 AND version = $2`, c.ID, c.Version, id); err != nil {
				return st, err
			}
			continue
		case !errors.Is(err, pgx.ErrNoRows):
			return st, err
		}
		pre, _ := json.Marshal(c.Preconditions)
		prov, _ := json.Marshal(c.Provenance)
		if _, err := tx.Exec(ctx, `INSERT INTO compliance_controls (id, version, pack_id, title, description, platforms, scopes, severity,
				executor, executor_ref, detect, expected, applicability, remediation_text, apply_supported, apply_ref, undo_ref, undo_kind,
				risk_tier, warning_id, needs_restart, preconditions, author, provenance, licence_class, review_state, body_sha256)
			VALUES ($1, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10, $11, $12, COALESCE($13::jsonb, '{}'), $14, $15, $16, $17, $18, $19,
				NULLIF($20, ''), $21, $22, $23, $24, $25, $26, $27)`,
			c.ID, c.Version, id, c.Title, c.Description, c.Platforms, c.Scopes, c.Severity, c.Executor, c.ExecutorRef, c.Detect, c.Expected,
			nullIfEmpty(c.Applicab), c.Remediation, c.ApplySupported, nullJSON(c.ApplyRef), nullJSON(c.UndoRef), c.UndoKind, c.RiskTier,
			c.WarningID, c.NeedsRestart, pre, c.Author, prov, string(c.LicenceClass), c.ReviewState, sum); err != nil {
			return st, fmt.Errorf("control %s: %w", c.ID, err)
		}
	}
	return st, nil
}

func nullJSON(b json.RawMessage) any {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	return []byte(b)
}

func nullIfEmpty(b json.RawMessage) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

func storePack(ctx context.Context, tx pgx.Tx, e content.Entry, f File) (Status, error) {
	h := f.Pack
	st := Status{Path: e.Path, Key: h.Key, Version: h.Version, Kind: h.Kind, State: StateLoaded}
	var id, oldHash string
	err := tx.QueryRow(ctx, `SELECT id::text, manifest_sha256 FROM compliance_packs WHERE key = $1 AND origin = 'builtin'`, h.Key).Scan(&id, &oldHash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		err = tx.QueryRow(ctx, `INSERT INTO compliance_packs (key, version, kind, title, origin, licence_class, source_id, review_state, review_ref, manifest_sha256)
			VALUES ($1, $2, $3, $4, 'builtin', $5, $6, $7, NULLIF($8, ''), $9) RETURNING id::text`,
			h.Key, h.Version, h.Kind, h.Title, string(h.LicenceClass), h.SourceID, h.ReviewState, h.ReviewRef, e.SHA256).Scan(&id)
		if err != nil {
			return st, err
		}
	case err != nil:
		return st, err
	case oldHash == e.SHA256:
		st.State = StateUnchanged
		return st, nil
	default:
		if _, err := tx.Exec(ctx, `UPDATE compliance_packs SET version = $2, kind = $3, title = $4, licence_class = $5, source_id = $6,
				review_state = $7, review_ref = NULLIF($8, ''), manifest_sha256 = $9 WHERE id = $1::uuid`,
			id, h.Version, h.Kind, h.Title, string(h.LicenceClass), h.SourceID, h.ReviewState, h.ReviewRef, e.SHA256); err != nil {
			return st, err
		}
		// A new version replaces what the pack held; enablement per organization stays.
		for _, q := range []string{`DELETE FROM compliance_mappings WHERE pack_id = $1::uuid`,
			`DELETE FROM compliance_frameworks WHERE pack_id = $1::uuid`, `DELETE FROM compliance_profiles WHERE pack_id = $1::uuid`} {
			if _, err := tx.Exec(ctx, q, id); err != nil {
				return st, err
			}
		}
	}
	if fw := f.Framework; fw != nil {
		if _, err := tx.Exec(ctx, `INSERT INTO compliance_frameworks (key, version, title, publisher, source_id, licence_class, text_policy, pack_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8::uuid)
			ON CONFLICT (key, version) DO UPDATE SET title = EXCLUDED.title, publisher = EXCLUDED.publisher, source_id = EXCLUDED.source_id,
				licence_class = EXCLUDED.licence_class, text_policy = EXCLUDED.text_policy, pack_id = EXCLUDED.pack_id`,
			fw.Key, fw.Version, fw.Title, fw.Publisher, fw.SourceID, string(h.LicenceClass), fw.TextPolicy, id); err != nil {
			return st, err
		}
		batch := &pgx.Batch{}
		for _, r := range f.Requirements {
			flags, _ := json.Marshal(r.Flags)
			batch.Queue(`INSERT INTO compliance_requirements (framework_key, framework_version, req_id, parent_id, title_own, text_full, class, weight, flags)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
				ON CONFLICT (framework_key, framework_version, req_id) DO UPDATE SET parent_id = EXCLUDED.parent_id, title_own = EXCLUDED.title_own,
					text_full = EXCLUDED.text_full, class = EXCLUDED.class, weight = EXCLUDED.weight, flags = EXCLUDED.flags`,
				fw.Key, fw.Version, r.ReqID, r.ParentID, r.TitleOwn, r.TextFull, r.Class, r.Weight, flags)
		}
		for _, o := range f.Objectives {
			batch.Queue(`INSERT INTO compliance_objectives (framework_key, framework_version, req_id, obj_id, text, methods) VALUES ($1, $2, $3, $4, $5, $6)`,
				fw.Key, fw.Version, o.ReqID, o.ObjID, o.Text, slices.Clone(o.Methods))
		}
		for _, m := range f.Rows() {
			prov, _ := json.Marshal(m.Prov)
			batch.Queue(`INSERT INTO compliance_mappings (pack_id, framework_key, framework_version, req_id, obj_id, control_id, relation, note, licence_class, provenance)
				VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9, $10)`,
				id, fw.Key, fw.Version, m.ReqID, m.ObjID, m.ControlID, m.Relation, m.Note, string(m.Licence), prov)
		}
		if err := sendBatch(ctx, tx, batch); err != nil {
			return st, fmt.Errorf("pack %s: %w", h.Key, err)
		}
	}
	for _, p := range f.Profiles {
		if _, err := tx.Exec(ctx, `INSERT INTO compliance_profiles (key, version, pack_id, title, platform, framework_key)
			VALUES ($1, $2, $3::uuid, $4, $5, $6)
			ON CONFLICT (key, version) DO UPDATE SET pack_id = EXCLUDED.pack_id, title = EXCLUDED.title, platform = EXCLUDED.platform,
				framework_key = EXCLUDED.framework_key`, p.Key, p.Version, id, p.Title, p.Platform, p.FrameworkKey); err != nil {
			return st, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM compliance_profile_controls WHERE profile_key = $1 AND profile_version = $2`, p.Key, p.Version); err != nil {
			return st, err
		}
		batch := &pgx.Batch{}
		for _, c := range p.Controls {
			params := c.Params
			if len(params) == 0 {
				params = json.RawMessage("{}")
			}
			batch.Queue(`INSERT INTO compliance_profile_controls (profile_key, profile_version, control_id, params) VALUES ($1, $2, $3, $4)`,
				p.Key, p.Version, c.ControlID, params)
		}
		if err := sendBatch(ctx, tx, batch); err != nil {
			return st, err
		}
	}
	return st, nil
}

func sendBatch(ctx context.Context, tx pgx.Tx, b *pgx.Batch) error {
	if b.Len() == 0 {
		return nil
	}
	br := tx.SendBatch(ctx, b)
	for i := 0; i < b.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return err
		}
	}
	return br.Close()
}
