package content

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Warning is our own warning text a fix is agreed under (ADR-0078, section
// 6). It is versioned: a changed text takes a new id (warn.t2.v2), and an
// agreement records the id and the hash of the text it was made under.
type Warning struct {
	ID             string   `json:"id"`
	Version        int      `json:"version"`
	Tier           string   `json:"tier"`
	Title          string   `json:"title"`
	Paragraphs     []string `json:"paragraphs"`
	UndoNote       string   `json:"undoNote"`
	TypedRequired  bool     `json:"typedRequired"`
	StepUpRequired bool     `json:"stepUpRequired"`
	// SHA256 is the hash of the text above, computed when the warnings load.
	SHA256 string `json:"sha256"`
}

//go:embed warnings
var warningFiles embed.FS

// Hash is the warning's hash: over its id, version, tier, title, every
// paragraph and the undo note, so a change to any of them changes it.
func (w Warning) Hash() string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%d\n%s\n%s\n%s\n%s\n", w.ID, w.Version, w.Tier, w.Title, strings.Join(w.Paragraphs, "\n"), w.UndoNote)
	return hex.EncodeToString(h.Sum(nil))
}

// Warnings loads the embedded warning texts by id.
func Warnings() (map[string]Warning, error) {
	ents, err := warningFiles.ReadDir("warnings")
	if err != nil {
		return nil, err
	}
	out := map[string]Warning{}
	for _, e := range ents {
		b, err := warningFiles.ReadFile("warnings/" + e.Name())
		if err != nil {
			return nil, err
		}
		var w Warning
		if err := json.Unmarshal(b, &w); err != nil {
			return nil, fmt.Errorf("warnings/%s: %w", e.Name(), err)
		}
		if w.ID == "" || w.Tier == "" || len(w.Paragraphs) == 0 || w.Title == "" {
			return nil, fmt.Errorf("warnings/%s: id, tier, title and text are needed", e.Name())
		}
		if _, dup := out[w.ID]; dup {
			return nil, fmt.Errorf("warnings/%s: %s is defined twice", e.Name(), w.ID)
		}
		w.SHA256 = w.Hash()
		out[w.ID] = w
	}
	return out, nil
}
