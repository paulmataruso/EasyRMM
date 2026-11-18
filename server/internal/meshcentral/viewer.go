package meshcentral

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

// webDir is the folder in the configuration directory that MeshCentral
// serves its pages' files from before its own (webPublicPath).
const webDir = "web"

// viewerScript tunes MeshCentral's session view (ADR-0025): sessions connect
// at once, the desktop is scaled to the size it is shown at, frames are
// asked for more often and decoded off the main thread.
//
//go:embed viewer.js
var viewerScript []byte

// ViewerScript returns the session view tuning MeshCentral's pages load.
func ViewerScript() []byte { return viewerScript }

// WriteWeb writes the files MeshCentral serves from EasyRMM's web folder in
// dir: the session view tuning as scripts/custom.js, the script every
// MeshCentral page loads after its own. MeshCentral reads the folder on each
// request, so a new version applies without a restart. It reports whether
// anything changed.
func WriteWeb(dir string) (bool, error) {
	scripts := filepath.Join(dir, webDir, "scripts")
	if err := os.MkdirAll(scripts, 0o700); err != nil {
		return false, fmt.Errorf("writing MeshCentral web files: %w", err)
	}
	changed, err := writeFile(filepath.Join(scripts, "custom.js"), viewerScript)
	if err != nil {
		return false, fmt.Errorf("writing MeshCentral web files: %w", err)
	}
	return changed, nil
}
