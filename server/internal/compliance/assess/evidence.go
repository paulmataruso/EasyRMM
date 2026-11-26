package assess

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// MaxEvidenceBytes is the largest evidence file: 64 MiB of plaintext.
const MaxEvidenceBytes = 64 << 20

// ErrTooLarge is an evidence file over the cap.
var ErrTooLarge = apperr.Invalid("file", "An evidence file can be at most 64 MiB.")

func dekAAD(org uuid.UUID) []byte { return []byte("easyrmm:compliance:dek:" + org.String()) }

func evidenceAAD(org, ev uuid.UUID) []byte {
	return []byte("easyrmm:compliance:evidence:" + org.String() + ":" + ev.String())
}

// encrypt seals plaintext with AES-256-GCM under key, with a fresh 96-bit nonce. The associated data
// binds the ciphertext to its organization and row.
func encrypt(key, aad, plain []byte) (nonce, ct []byte, err error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, g.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, g.Seal(nil, nonce, plain, aad), nil
}

func decrypt(key, aad, nonce, ct []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, nonce, ct, aad)
}

// dataKey is the organization's current evidence data key, made on first use and wrapped by the
// server's sealer. The wrapped key is re-sealed when the master key has rotated; blobs are untouched.
func (s *Service) dataKey(ctx context.Context, org uuid.UUID, keyID string) (string, []byte, error) {
	var id string
	var dek []byte
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var wrapped string
		q := `SELECT key_id, wrapped FROM compliance_org_keys WHERE organization_id = $1 ORDER BY created_at DESC, key_id DESC LIMIT 1`
		args := []any{org}
		if keyID != "" {
			q = `SELECT key_id, wrapped FROM compliance_org_keys WHERE organization_id = $1 AND key_id = $2`
			args = append(args, keyID)
		}
		err := tx.QueryRow(ctx, q, args...).Scan(&id, &wrapped)
		if errors.Is(err, pgx.ErrNoRows) && keyID == "" {
			key := make([]byte, 32)
			if _, err := io.ReadFull(rand.Reader, key); err != nil {
				return err
			}
			w, err := s.sealer.Seal(key, dekAAD(org))
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO compliance_org_keys (organization_id, key_id, wrapped) VALUES ($1, 'k1', $2) ON CONFLICT DO NOTHING`, org, w); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, q, args...).Scan(&id, &wrapped); err != nil {
				return err
			}
		} else if err != nil {
			return err
		}
		dek, err = s.sealer.Open(wrapped, dekAAD(org))
		if err != nil {
			return fmt.Errorf("evidence data key: %w", err)
		}
		if s.sealer.NeedsReseal(wrapped) {
			w, err := s.sealer.Seal(dek, dekAAD(org))
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE compliance_org_keys SET wrapped = $3 WHERE organization_id = $1 AND key_id = $2`, org, id, w); err != nil {
				return err
			}
		}
		return nil
	})
	return id, dek, err
}

// EvidenceView is a piece of evidence as listed: never the body.
type EvidenceView struct {
	ID           uuid.UUID  `json:"id"`
	Kind         string     `json:"kind"`
	Title        string     `json:"title"`
	MediaType    string     `json:"mediaType"`
	FileName     string     `json:"fileName"`
	Size         *int64     `json:"size"`
	URL          string     `json:"url"`
	SHA256       string     `json:"sha256"`
	CollectedAt  time.Time  `json:"collectedAt"`
	Collector    *uuid.UUID `json:"collector"`
	ExpiresAt    *time.Time `json:"expiresAt"`
	SupersededBy *uuid.UUID `json:"supersededBy"`
	Expired      bool       `json:"expired"`
}

const evidenceCols = `id, kind, title, coalesce(media_type, ''), coalesce(file_name, ''), size_bytes, coalesce(url, ''), sha256, collected_at, collector, expires_at, superseded_by`

func scanEvidence(row pgx.Row, now time.Time) (EvidenceView, error) {
	var v EvidenceView
	err := row.Scan(&v.ID, &v.Kind, &v.Title, &v.MediaType, &v.FileName, &v.Size, &v.URL, &v.SHA256, &v.CollectedAt, &v.Collector, &v.ExpiresAt, &v.SupersededBy)
	v.Expired = v.ExpiresAt != nil && !now.Before(*v.ExpiresAt)
	return v, err
}

// EvidenceInput is a new piece of evidence. For a file, Body is its contents; for a link, URL.
type EvidenceInput struct {
	Kind      string
	Title     string
	MediaType string
	FileName  string
	URL       string
	Body      io.Reader
	ExpiresAt *time.Time
	// Link attaches it where it belongs, when set.
	AssessmentID *uuid.UUID
	ReqID        string
	ObjID        string
	PoamID       *uuid.UUID
	// Supersedes names the evidence this replaces.
	Supersedes *uuid.UUID
}

func (in *EvidenceInput) validate() error {
	f := apperr.Fields{}
	f.Check(trim(in.Title) != "" && len(in.Title) <= 300, "title", "Give it a title of up to 300 characters.")
	f.Check(len(in.MediaType) <= 200 && len(in.FileName) <= 300, "file", "The file's type or name is too long.")
	if in.Kind == "" {
		in.Kind = "upload"
	}
	switch in.Kind {
	case "upload", "screenshot", "scan_snapshot":
		f.Check(in.Body != nil, "file", "Send the file as the request body.")
	case "link":
		u, err := url.Parse(in.URL)
		f.Check(err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && len(in.URL) <= 2000, "url", "Give a web address starting with https://.")
	default:
		f.Check(false, "kind", "Choose upload, screenshot or link.")
	}
	if in.ReqID != "" || in.ObjID != "" {
		f.Check(in.AssessmentID != nil, "assessmentId", "Name the assessment the requirement belongs to.")
	}
	f.Check(in.ObjID == "" || in.ReqID != "", "reqId", "Name the requirement the objective belongs to.")
	return f.Err()
}

// AddEvidence stores a piece of evidence. A file is read in full up to the cap, its SHA-256 taken of
// the plaintext, and then encrypted under the organization's data key. Evidence is never deleted.
func (s *Service) AddEvidence(ctx context.Context, c access.Caller, org uuid.UUID, in EvidenceInput) (*EvidenceView, error) {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
		return nil, err
	}
	if err := in.validate(); err != nil {
		return nil, err
	}
	var plain []byte
	if in.Kind != "link" {
		var err error
		if plain, err = readCapped(in.Body); err != nil {
			return nil, err
		}
	}
	sum := sha256.Sum256(plain)
	if in.Kind == "link" {
		sum = sha256.Sum256([]byte(in.URL))
	}
	hash := hex.EncodeToString(sum[:])
	id := uuid.New()
	var nonce, ct []byte
	var keyID string
	if in.Kind != "link" {
		var dek []byte
		var err error
		if keyID, dek, err = s.dataKey(ctx, org, ""); err != nil {
			return nil, err
		}
		if nonce, ct, err = encrypt(dek, evidenceAAD(org, id), plain); err != nil {
			return nil, err
		}
	}
	var out EvidenceView
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var size *int64
		var body any
		var u any
		var kid, n any
		if in.Kind == "link" {
			u = in.URL
		} else {
			sz := int64(len(plain))
			size, body, kid, n = &sz, ct, keyID, nonce
		}
		var old *EvidenceView
		if in.Supersedes != nil {
			o, err := scanEvidence(tx.QueryRow(ctx, `SELECT `+evidenceCols+` FROM compliance_evidence WHERE id = $1 AND organization_id = $2`, *in.Supersedes, org), s.now())
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return apperr.NotFound()
				}
				return err
			}
			if o.SupersededBy != nil {
				return apperr.Conflict("already_superseded", "That evidence has already been replaced.")
			}
			old = &o
		}
		v, err := scanEvidence(tx.QueryRow(ctx, `INSERT INTO compliance_evidence (id, organization_id, kind, title, media_type, file_name, size_bytes, body, nonce, key_id, url, sha256, collector, expires_at)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8, $9, $10, $11, $12, $13, $14) RETURNING `+evidenceCols,
			id, org, in.Kind, trim(in.Title), in.MediaType, in.FileName, size, body, n, kid, u, hash, nilUser(c), in.ExpiresAt), s.now())
		if err != nil {
			return err
		}
		out = v
		action := "compliance.evidence.upload"
		det := map[string]any{"evidence": id, "kind": in.Kind, "sha256": hash, "size": size}
		if old != nil {
			if _, err := tx.Exec(ctx, `UPDATE compliance_evidence SET superseded_by = $2 WHERE id = $1`, old.ID, id); err != nil {
				return err
			}
			// The new item takes the old one's place wherever it is linked and still can be changed.
			if _, err := tx.Exec(ctx, `INSERT INTO compliance_evidence_links (organization_id, evidence_id, assessment_id, req_id, obj_id, poam_id, fix_item_id, linked_by)
				SELECT l.organization_id, $2, l.assessment_id, l.req_id, l.obj_id, l.poam_id, l.fix_item_id, $3 FROM compliance_evidence_links l
				LEFT JOIN compliance_assessments a ON a.id = l.assessment_id LEFT JOIN compliance_poam_items p ON p.id = l.poam_id
				LEFT JOIN compliance_assessments pa ON pa.id = p.assessment_id
				WHERE l.evidence_id = $1 AND coalesce(a.state, 'draft') IN ('draft', 'in_review') AND coalesce(pa.state, 'draft') IN ('draft', 'in_review')`, old.ID, id, nilUser(c)); err != nil {
				return err
			}
			action, det["supersedes"] = "compliance.evidence.supersede", old.ID
		}
		if err := s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: action, OrganizationID: org, TargetType: "compliance_evidence", TargetID: id.String(),
			Outcome: audit.Success, Details: det}); err != nil {
			return err
		}
		if in.AssessmentID != nil || in.PoamID != nil {
			return s.link(ctx, tx, c, org, id, in.AssessmentID, in.ReqID, in.ObjID, in.PoamID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// readCapped reads a body, failing past the cap.
func readCapped(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxEvidenceBytes+1))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, ErrTooLarge
		}
		return nil, err
	}
	if len(b) > MaxEvidenceBytes {
		return nil, ErrTooLarge
	}
	return b, nil
}

// LinkEvidence attaches existing evidence to a requirement, an objective or a plan-of-action item.
func (s *Service) LinkEvidence(ctx context.Context, c access.Caller, org, evidence uuid.UUID, assessment *uuid.UUID, req, obj string, poam *uuid.UUID) error {
	if err := need(c, rbac.PermComplianceEdit, org); err != nil {
		return err
	}
	if assessment == nil && poam == nil {
		return apperr.Invalid("assessmentId", "Name an assessment or a plan-of-action item.")
	}
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM compliance_evidence WHERE id = $1 AND organization_id = $2`, evidence, org).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return apperr.NotFound()
		}
		return s.link(ctx, tx, c, org, evidence, assessment, req, obj, poam)
	})
}

func (s *Service) link(ctx context.Context, tx pgx.Tx, c access.Caller, org, evidence uuid.UUID, assessment *uuid.UUID, req, obj string, poam *uuid.UUID) error {
	if assessment != nil {
		a, err := load(ctx, tx, org, *assessment)
		if err != nil {
			return err
		}
		if err := editable(a); err != nil {
			return err
		}
		if req != "" {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM compliance_implementations WHERE assessment_id = $1 AND req_id = $2`, a.ID, req).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return apperr.NotFound()
			}
		}
	}
	if poam != nil {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM compliance_poam_items WHERE id = $1 AND organization_id = $2`, *poam, org).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return apperr.NotFound()
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO compliance_evidence_links (organization_id, evidence_id, assessment_id, req_id, obj_id, poam_id, linked_by)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), $6, $7)`, org, evidence, assessment, req, obj, poam, nilUser(c)); err != nil {
		return err
	}
	return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "compliance.evidence.link", OrganizationID: org, TargetType: "compliance_evidence", TargetID: evidence.String(),
		Outcome: audit.Success, Details: map[string]any{"assessment": assessment, "req": req, "objective": obj, "poam": poam}})
}

// ListEvidence lists an organization's evidence, newest first; with onlyLive, without what has been replaced.
func (s *Service) ListEvidence(ctx context.Context, c access.Caller, org uuid.UUID, onlyLive bool) ([]EvidenceView, error) {
	if err := need(c, rbac.PermComplianceView, org); err != nil {
		return nil, err
	}
	out := []EvidenceView{}
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+evidenceCols+` FROM compliance_evidence WHERE organization_id = $1 AND (NOT $2 OR superseded_by IS NULL) ORDER BY collected_at DESC LIMIT 500`, org, onlyLive)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scanEvidence(rows, s.now())
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

func evidenceFor(ctx context.Context, tx pgx.Tx, org, assessment uuid.UUID, req string) ([]EvidenceView, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT e.id, e.kind, e.title, coalesce(e.media_type, ''), coalesce(e.file_name, ''), e.size_bytes, coalesce(e.url, ''), e.sha256, e.collected_at,
		e.collector, e.expires_at, e.superseded_by FROM compliance_evidence e JOIN compliance_evidence_links l ON l.evidence_id = e.id
		WHERE l.assessment_id = $1 AND l.req_id = $2 AND e.organization_id = $3 ORDER BY e.collected_at DESC`, assessment, req, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EvidenceView{}
	for rows.Next() {
		v, err := scanEvidence(rows, time.Now())
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Download is evidence's plaintext.
type Download struct {
	EvidenceView
	Body []byte
}

// DownloadEvidence returns an evidence file after checking its SHA-256 against the one recorded
// when it was stored. Every download is audited: who, which, its hash, and from where (the actor
// carries the source address).
func (s *Service) DownloadEvidence(ctx context.Context, c access.Caller, org, id uuid.UUID) (*Download, error) {
	if err := need(c, rbac.PermComplianceView, org); err != nil {
		return nil, err
	}
	var d Download
	var ct, nonce []byte
	var keyID string
	err := s.db.ReadTx(ctx, c.Scope, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+evidenceCols+`, body, nonce, coalesce(key_id, '') FROM compliance_evidence WHERE id = $1 AND organization_id = $2`, id, org)
		return row.Scan(&d.ID, &d.Kind, &d.Title, &d.MediaType, &d.FileName, &d.Size, &d.URL, &d.SHA256, &d.CollectedAt, &d.Collector, &d.ExpiresAt, &d.SupersededBy, &ct, &nonce, &keyID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound()
	}
	if err != nil {
		return nil, err
	}
	if d.Kind == "link" {
		return nil, apperr.Conflict("is_link", "This evidence is a link, not a file.")
	}
	_, dek, err := s.dataKey(ctx, org, keyID)
	if err != nil {
		return nil, err
	}
	plain, err := decrypt(dek, evidenceAAD(org, id), nonce, ct)
	if err != nil {
		s.denied(ctx, c, org, id, "the stored file could not be decrypted")
		return nil, apperr.Conflict("evidence_unreadable", "The stored file could not be decrypted. It is not returned.")
	}
	sum := sha256.Sum256(plain)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(d.SHA256)) != 1 {
		s.denied(ctx, c, org, id, "the stored file does not match its recorded SHA-256")
		return nil, apperr.Conflict("evidence_changed", "The stored file does not match its recorded SHA-256. It is not returned.")
	}
	err = s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "compliance.evidence.download", OrganizationID: org, TargetType: "compliance_evidence",
			TargetID: id.String(), Outcome: audit.Success, Details: map[string]any{"evidence": id, "sha256": d.SHA256, "title": d.Title}})
	})
	if err != nil {
		return nil, err
	}
	d.Body = plain
	return &d, nil
}

// denied records a download that was refused because the file did not check out.
func (s *Service) denied(ctx context.Context, c access.Caller, org, id uuid.UUID, why string) {
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return s.audit.Write(ctx, tx, audit.Event{Actor: c.Actor, Action: "compliance.evidence.download", OrganizationID: org, TargetType: "compliance_evidence",
			TargetID: id.String(), Outcome: audit.Failure, Details: map[string]any{"evidence": id, "reason": why}})
	})
	if err != nil {
		s.log.Error("audit of a refused evidence download failed", "err", err)
	}
}
