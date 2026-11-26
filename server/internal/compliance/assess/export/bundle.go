package export

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess/oscal"
	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess/report"
)

// File is one file of the bundle.
type File struct {
	Name string
	Body []byte
}

// ManifestEntry is a file of the bundle and its SHA-256.
type ManifestEntry struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

// Bundle is every export in one ZIP, with a MANIFEST.json listing each file's SHA-256. Evidence
// bodies are not in it: a bundle may leave the platform, and the evidence is listed by hash.
func Bundle(r *report.Report) ([]byte, error) {
	ssp, err := oscal.SSP(r)
	if err != nil {
		return nil, err
	}
	poam, err := oscal.POAM(r)
	if err != nil && !errors.Is(err, oscal.ErrNoItems) {
		return nil, err
	}
	req, err := Requirements(r)
	if err != nil {
		return nil, err
	}
	pc, err := POAM(r)
	if err != nil {
		return nil, err
	}
	score, err := json.MarshalIndent(r.Score, "", "  ")
	if err != nil {
		return nil, err
	}
	files := []File{{"ssp.oscal.json", ssp}, {"requirements.csv", req}, {"poam.csv", pc}, {"report.pdf", PDF(r)}, {"score.json", score}}
	if poam != nil {
		files = append(files, File{"poam.oscal.json", poam})
	}
	var man []ManifestEntry
	for _, f := range files {
		h := sha256.Sum256(f.Body)
		man = append(man, ManifestEntry{Name: f.Name, SHA256: hex.EncodeToString(h[:]), Size: len(f.Body)})
	}
	sort.Slice(man, func(i, j int) bool { return man[i].Name < man[j].Name })
	mb, err := json.MarshalIndent(map[string]any{"assessmentId": r.AssessmentID, "generated": r.Generated.UTC().Format(time.RFC3339), "files": man}, "", "  ")
	if err != nil {
		return nil, err
	}
	files = append(files, File{"MANIFEST.json", mb})
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, f := range files {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: zip.Deflate, Modified: r.Generated.UTC()})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.Body); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
