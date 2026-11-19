package reports

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// Patch reports (one-product plan, C5) come from the patching engine
// rather than from EasyRMM's database. The engine already keeps to what
// the caller may see; Run checks report.view and
// patch.view at each row's site besides.

// PatchSource is the patching engine's client as the patch reports read it. The
// app wires it with UsePatching; without it the patch reports are not found.
type PatchSource interface {
	// PatchDevices lists the devices whose patching the caller sees, in
	// order; truncated says there were more than the source lists.
	PatchDevices(ctx context.Context, c access.Caller, q Query) (devices []PatchDevice, truncated bool, err error)
	// PatchInstallations lists the updates EasyPatch's jobs finished with
	// over q.Days, newest first.
	PatchInstallations(ctx context.Context, c access.Caller, q Query) (rows []PatchInstallation, truncated bool, err error)
}

// PatchDevice is a device and what EasyPatch says about its updates.
type PatchDevice struct {
	OrganizationID, SiteID     uuid.UUID
	Organization, Site, Device string
	Platform                   string
	// Linked says EasyPatch patches the device; NotPatched says why not
	// when it does not.
	Linked     bool
	NotPatched string
	// The rest is EasyPatch's, when the device is linked.
	OS, OSBuild, OSSupport        string
	Compliance                    string
	MissingRequired, MissingTotal int
	Failed, KnownExploited        int
	RestartPending, Online        bool
	LastScan, LastCheckIn         *time.Time
}

// PatchInstallation is an update a job finished with on a device.
type PatchInstallation struct {
	OrganizationID, SiteID     uuid.UUID
	Organization, Site, Device string
	CompletedAt                time.Time
	KB, Title, Category        string
	Result, Detail             string
	RestartRequired            bool
	RequestedBy                string
	JobID                      uuid.UUID
}

// UsePatching gives the patch reports their source.
func (s *Service) UsePatching(src PatchSource) { s.patch = src }

var complianceLabels = map[string]string{
	"Compliant":      "Up to date",
	"MissingUpdates": "Updates missing",
	"FailedUpdates":  "Updates failed",
	"RebootRequired": "Restart needed",
	"ScanStale":      "Scan out of date",
	"NeverScanned":   "Never scanned",
}

var supportLabels = map[string]string{
	"Supported":               "Supported",
	"ExtendedSecurityUpdates": "Extended security updates",
	"Unsupported":             "No longer supported",
	"Unknown":                 "",
}

var categoryLabels = map[string]string{"ServicingStack": "Servicing stack", "DotNet": ".NET"}

var resultLabels = map[string]string{
	"Succeeded": "Installed",
	"Failed":    "Failed",
	"Skipped":   "Skipped",
	"Cancelled": "Cancelled", //nolint:misspell // EasyPatch's enum value, and the console's British label
}

func label(labels map[string]string, v string) string {
	if l, ok := labels[v]; ok {
		return l
	}
	return v
}

// --- Patch compliance --------------------------------------------------------

var patchComplianceReport = definition{
	title: "Patch compliance",
	perm:  rbac.PermPatchView,
	columns: []Column{
		{"organization", "Organization", TypeText},
		{"site", "Site", TypeText},
		{"device", "Device", TypeText},
		{"platform", "Platform", TypeText},
		{"compliance", "Compliance", TypeText},
		{"notPatched", "Not patched because", TypeText},
		{"missingRequired", "Required updates missing", TypeNumber},
		{"missingTotal", "Updates missing", TypeNumber},
		{"failed", "Updates failed", TypeNumber},
		{"knownExploited", "Known exploited", TypeNumber},
		{"restartPending", "Restart pending", TypeBool},
		{"os", "Operating system", TypeText},
		{"osBuild", "Build", TypeText},
		{"osSupport", "OS support", TypeText},
		{"online", "Online in EasyPatch", TypeBool},
		{"lastScan", "Last scan", TypeTime},
		{"lastCheckIn", "Last EasyPatch check-in", TypeTime},
	},
	patch: func(ctx context.Context, src PatchSource, c access.Caller, q Query, out emit) (bool, error) {
		devices, truncated, err := src.PatchDevices(ctx, c, q)
		if err != nil {
			return false, err
		}
		for _, d := range devices {
			if q.Platform != "" && d.Platform != q.Platform {
				continue
			}
			row := []any{d.Organization, d.Site, d.Device, platformName(d.Platform)}
			if !d.Linked {
				row = append(row, "Not patched", d.NotPatched, nil, nil, nil, nil, nil, "", "", "", nil, nil, nil)
			} else {
				row = append(row, label(complianceLabels, d.Compliance), "", d.MissingRequired, d.MissingTotal, d.Failed, d.KnownExploited,
					d.RestartPending, d.OS, d.OSBuild, label(supportLabels, d.OSSupport), d.Online, timeOrNil(d.LastScan), timeOrNil(d.LastCheckIn))
			}
			if !out(d.OrganizationID, d.SiteID, row) {
				return truncated, nil
			}
		}
		return truncated, nil
	},
}

// --- Patch installations -----------------------------------------------------

var patchInstallationsReport = definition{
	title: "Patch installations",
	perm:  rbac.PermPatchView,
	columns: []Column{
		{"completed", "Finished", TypeTime},
		{"organization", "Organization", TypeText},
		{"site", "Site", TypeText},
		{"device", "Device", TypeText},
		{"kb", "KB", TypeText},
		{"update", "Update", TypeText},
		{"category", "Category", TypeText},
		{"result", "Result", TypeText},
		{"detail", "Detail", TypeText},
		{"restartRequired", "Restart required", TypeBool},
		{"requestedBy", "Requested by", TypeText},
		{"job", "Job", TypeText},
	},
	patch: func(ctx context.Context, src PatchSource, c access.Caller, q Query, out emit) (bool, error) {
		rows, truncated, err := src.PatchInstallations(ctx, c, q)
		if err != nil {
			return false, err
		}
		for _, r := range rows {
			row := []any{r.CompletedAt.UTC(), r.Organization, r.Site, r.Device, r.KB, r.Title, label(categoryLabels, r.Category),
				label(resultLabels, r.Result), r.Detail, r.RestartRequired, r.RequestedBy, r.JobID.String()}
			if !out(r.OrganizationID, r.SiteID, row) {
				return truncated, nil
			}
		}
		return truncated, nil
	},
}
