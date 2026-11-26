// Package backup is the catalog of ADR-0077's Windows Backup actions: Windows
// Server Backup on servers (policy, run now, history, versions, restore of
// files, pruning, installing the feature). Desktops are watched, not managed:
// the deprecated System Image Backup option and the File History policy switch
// wait for the real-device test R11 (see DesktopImageVerified).
//
// Every action is a script in scripts/, pinned by the SHA-256 of the text the
// agent receives: the action's file with the shared library files
// (_common.ps1 and, for share credentials, _credential.ps1) put in where it
// says "#@library". Changing a script or a library changes a hash in
// pins.go, in review.
package backup

import (
	"embed"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

//go:embed scripts/*.ps1
var scriptFS embed.FS

// DesktopImageVerified says the real-device test R11 passed (ADR-0077,
// section 5), which is what lets the desktop actions (option A and the File
// History switch) be built. It is false: R11 has not been run, so no desktop
// action is in the catalog and the server offers none.
const DesktopImageVerified = false

// Tiers (ADR-0077, "Risk tiers"). Tier 0 reads; tier 1 starts or ends work;
// tier 2 changes configuration and is confirmed; tier 3 loses data or stops
// protection, needs backup.destroy, a confirmation and a step-up.
const (
	tier0 = iota
	tier1
	tier2
	tier3
)

// Results.

// Target is one backup target as status shows it, without its path.
type Target struct {
	Kind       string `json:"kind"`
	FreeBytes  *int64 `json:"freeBytes"`
	TotalBytes *int64 `json:"totalBytes"`
	Online     bool   `json:"online"`
}

// Job is one backup or recovery job.
type Job struct {
	Type            string     `json:"type"`
	State           string     `json:"state"`
	StartTime       *time.Time `json:"startTime"`
	EndTime         *time.Time `json:"endTime"`
	Percent         *int64     `json:"percent"`
	HResult         *int64     `json:"hresult"`
	DetailedHResult *int64     `json:"detailedHResult"`
}

// Status is backup.status's result. Installed false is a server without the
// feature (the other fields are then empty).
type Status struct {
	Installed          bool       `json:"installed"`
	Configured         bool       `json:"configured"`
	Running            bool       `json:"running"`
	NextRun            *time.Time `json:"nextRun"`
	LastSuccess        *time.Time `json:"lastSuccess"`
	LastFailure        *time.Time `json:"lastFailure"`
	LastResultHR       *int64     `json:"lastResultHR"`
	LastSuccessAgeDays *int       `json:"lastSuccessAgeDays"`
	VersionCount       *int       `json:"versionCount"`
	OldestVersion      *time.Time `json:"oldestVersion"`
	NewestVersion      *time.Time `json:"newestVersion"`
	Schedule           []string   `json:"schedule"`
	SystemState        bool       `json:"systemState"`
	BareMetal          bool       `json:"bareMetal"`
	VolumeCount        int        `json:"volumeCount"`
	FileSpecCount      int        `json:"fileSpecCount"`
	VSSFull            bool       `json:"vssFull"`
	Targets            []Target   `json:"targets"`
	Job                *Job       `json:"job"`
}

// SensitiveTarget names a target: its path, share and kind.
type SensitiveTarget struct {
	Path  string `json:"path"`
	Label string `json:"label"`
	Kind  string `json:"kind"`
}

// Sensitive is backup.sensitive's result: what names customers and users.
type Sensitive struct {
	Targets []SensitiveTarget `json:"targets"`
	Include []string          `json:"include"`
	Exclude []string          `json:"exclude"`
}

// Version is one backup set.
type Version struct {
	ID        string     `json:"id"`
	Time      *time.Time `json:"time"`
	SizeBytes *int64     `json:"sizeBytes"`
	Kinds     []string   `json:"kinds"`
}

// Versions is backup.versions' result.
type Versions struct {
	Versions []Version `json:"versions"`
}

// DiskVolume is a volume on a candidate disk.
type DiskVolume struct {
	Label     string `json:"label"`
	SizeBytes *int64 `json:"sizeBytes"`
	FreeBytes *int64 `json:"freeBytes"`
}

// Disk is a candidate target disk. Adding one as a target formats it.
type Disk struct {
	Number    *int64       `json:"number"`
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	SizeBytes *int64       `json:"sizeBytes"`
	Online    bool         `json:"online"`
	HasData   bool         `json:"hasData"`
	Volumes   []DiskVolume `json:"volumes"`
}

// Disks is backup.disks' result.
type Disks struct {
	Disks []Disk `json:"disks"`
}

// Jobs is backup.job's result.
type Jobs struct {
	Running bool  `json:"running"`
	Jobs    []Job `json:"jobs"`
}

// Done is the result of an action that has nothing to report.
type Done struct {
	Done bool `json:"done"`
}

// NetworkDone says the share target is set and its credential stored by
// Windows; it never carries the credential.
type NetworkDone struct {
	Done          bool `json:"done"`
	CredentialSet bool `json:"credentialSet"`
}

// Restore is the result of starting a restore; progress is read with
// backup.job.
type Restore struct {
	Started    bool   `json:"started"`
	TargetPath string `json:"targetPath"`
}

// PruneSet is a backup version a prune would remove.
type PruneSet struct {
	ID   string     `json:"id"`
	Time *time.Time `json:"time"`
}

// PrunePreview lists what a prune would remove.
type PrunePreview struct {
	Total int        `json:"total"`
	Sets  []PruneSet `json:"sets"`
}

// Pruned is the result of removing versions.
type Pruned struct {
	Removed   int `json:"removed"`
	Remaining int `json:"remaining"`
}

// Installed is feature_install's result.
type Installed struct {
	Installed        bool `json:"installed"`
	RestartNeeded    bool `json:"restartNeeded"`
	AlreadyInstalled bool `json:"alreadyInstalled"`
}

// Parameter forms.

var (
	timesPattern    = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d(,([01]\d|2[0-3]):[0-5]\d){0,5}$`)
	volumePattern   = regexp.MustCompile(`^([A-Za-z]:|\\\\\?\\Volume\{[0-9A-Fa-f-]{36}\}\\)$`)
	volumesPattern  = regexp.MustCompile(`^[A-Za-z]:(\|[A-Za-z]:){0,25}$`)
	uncPattern      = regexp.MustCompile(`^\\\\[A-Za-z0-9][A-Za-z0-9._-]{0,254}(\\[^\\/:*?"<>|\x00-\x1f]{1,80}){2,}$`)
	accountPattern  = regexp.MustCompile(`^([A-Za-z0-9._-]{1,64}\\)?[A-Za-z0-9._@$ -]{1,104}$`)
	versionPattern  = regexp.MustCompile(`^(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}|\{?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}?)$`)
	diskIDPattern   = regexp.MustCompile(`^[A-Za-z0-9{}\-_. ]{1,128}$`)
	drivePathPrefix = regexp.MustCompile(`^[A-Za-z]:\\`)
)

// noDotSegments refuses a . or .. part in a path or share name.
func noDotSegments(s string) string {
	for _, seg := range strings.FieldsFunc(s, func(r rune) bool { return r == '\\' || r == '/' }) {
		if seg == "." || seg == ".." {
			return "The path must not contain . or .. parts."
		}
	}
	return ""
}

func uncCheck(s string) string {
	if len(s) > 260 {
		return "The share path is too long."
	}
	return noDotSegments(s)
}

// pathList checks a list of absolute drive paths separated by "|" (a
// character no path holds): at most 20, each at most 260 characters.
func pathList(s string) string {
	parts := strings.Split(s, "|")
	if len(parts) > 20 {
		return "Give at most 20 paths."
	}
	for _, p := range parts {
		switch {
		case len(p) > 260 || !drivePathPrefix.MatchString(p):
			return "Each path must be absolute, such as C:\\Data, and at most 260 characters."
		case strings.ContainsAny(p, "/<>\"?*") || strings.Contains(p[2:], ":"):
			return "A path holds a character that is not allowed."
		}
		if msg := noDotSegments(p); msg != "" {
			return msg
		}
	}
	return ""
}

func device() winmod.Param {
	return winmod.Param{Name: "device", Type: winmod.Name, Required: true, Max: 64}
}

func text(name string, max int, re *regexp.Regexp, check func(string) string) winmod.Param {
	return winmod.Param{Name: name, Type: winmod.Text, Required: true, Max: max, Pattern: re, Check: check}
}

func optional(p winmod.Param) winmod.Param { p.Required = false; return p }

func library(file string) string {
	b, err := scriptFS.ReadFile("scripts/" + file)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Script is the text of an action's script as the agent receives it: the
// action's file with the library files put in where it says "#@library".
func Script(file string) string {
	s := library(file + ".ps1")
	s = strings.Replace(s, "#@library common\n", library("_common.ps1"), 1)
	return strings.Replace(s, "#@library credential\n", library("_credential.ps1"), 1)
}

// entry builds a catalog action of a tier. The script is `file` (also the
// key of its pin).
func entry(tier int, file, label string, timeout int, decode func(json.RawMessage) (json.RawMessage, error), params ...winmod.Param) winmod.Action {
	a := winmod.Action{
		Module: modules.WindowsBackup, Name: "windows_backup." + file, Label: label, Version: 1,
		Script: Script(file), ScriptSHA256: pins[file], Params: params, Timeout: timeout, Decode: decode,
	}
	switch tier {
	case tier0:
		a.Permission, a.Keep = rbac.PermBackupView, time.Hour
	case tier1:
		a.Permission, a.Keep, a.Changes = rbac.PermBackupManage, 7*24*time.Hour, true
	case tier2:
		a.Permission, a.Keep, a.Changes = rbac.PermBackupManage, 7*24*time.Hour, true
		a.Confirm, a.Subject = true, "device"
	case tier3:
		// backup.destroy is held by Site Administrators and above, who hold
		// backup.manage too, so one permission expresses "manage and destroy".
		a.Permission, a.Keep, a.Changes = rbac.PermBackupDestroy, 7*24*time.Hour, true
		a.Destructive, a.Subject = true, "device"
	}
	return a
}

// Actions are the Windows Backup actions the server can run.
func Actions() []winmod.Action {
	status := entry(tier0, "status", "Read the backup state", 60, winmod.Typed[Status]())
	// The alerts of alerts.go read this snapshot, which the server refreshes
	// hourly on every server that has Windows Server Backup.
	status.Freshness, status.Schedule = 5*time.Minute, time.Hour

	sensitive := entry(tier0, "sensitive", "Read the backup targets and items", 60, winmod.Typed[Sensitive]())
	sensitive.Sensitive, sensitive.SensitivePermission, sensitive.Keep = true, rbac.PermBackupViewSensitive, 15*time.Minute

	prune := winmod.Param{Name: "keep", Type: winmod.Int, Min: 1, Max: 365}
	restoreParams := []winmod.Param{
		device(), text("version", 64, versionPattern, nil),
		{Name: "source", Type: winmod.Path, Required: true, Max: 260},
		{Name: "recursive", Type: winmod.Bool},
	}
	return []winmod.Action{
		status, sensitive,
		entry(tier0, "versions", "List the backup versions", 60, winmod.Typed[Versions]()),
		entry(tier0, "disks", "List the disks that can hold backups", 60, winmod.Typed[Disks]()),
		entry(tier0, "job", "Read backup job progress", 30, winmod.Typed[Jobs](),
			winmod.Param{Name: "previous", Type: winmod.Int, Min: 0, Max: 20}),
		entry(tier1, "run_now", "Run the backup now", 60, winmod.Typed[Done]()),
		entry(tier1, "stop", "Stop the running backup", 60, winmod.Typed[Done]()),
		entry(tier2, "stop_recovery", "Stop the running restore", 60, winmod.Typed[Done](), device()),
		entry(tier2, "policy_set", "Set the backup policy", 120, winmod.Typed[Done](),
			device(),
			text("times", 40, timesPattern, nil),
			optional(text("volumes", 100, volumesPattern, nil)),
			optional(text("files", 2048, nil, pathList)),
			optional(text("exclude", 2048, nil, pathList)),
			winmod.Param{Name: "systemState", Type: winmod.Bool},
			winmod.Param{Name: "bareMetal", Type: winmod.Bool},
			optional(text("targetVolume", 60, volumePattern, nil))),
		entry(tier2, "target_network_set", "Back up to a network share", 120, winmod.Typed[NetworkDone](),
			device(),
			winmod.Param{Name: "unc", Type: winmod.Text, Required: true, Max: 260, Pattern: uncPattern, Check: uncCheck, Sensitive: true},
			winmod.Param{Name: "user", Type: winmod.Text, Required: true, Max: 170, Pattern: accountPattern, Sensitive: true},
			winmod.Param{Name: "password", Type: winmod.Text, Required: true, Max: 256, Secret: true}),
		entry(tier2, "target_volume_set", "Back up to a local volume", 120, winmod.Typed[Done](),
			device(), text("volume", 60, volumePattern, nil)),
		entry(tier3, "target_disk_set", "Back up to a whole disk (formats it)", 300, winmod.Typed[Done](),
			device(),
			winmod.Param{Name: "diskNumber", Type: winmod.Int, Required: true, Min: 0, Max: 1000},
			text("diskId", 128, diskIDPattern, nil)),
		entry(tier3, "vss_full_set", "Choose full or copy backups", 60, winmod.Typed[Done](),
			device(), winmod.Param{Name: "enabled", Type: winmod.Bool, Required: true}),
		entry(tier3, "policy_remove", "Remove the backup policy", 60, winmod.Typed[Done](), device()),
		entry(tier2, "restore_files", "Restore files to a new folder", 60, winmod.Typed[Restore](),
			append(slices.Clone(restoreParams), winmod.Param{Name: "targetPath", Type: winmod.Path, Max: 260})...),
		entry(tier3, "restore_files_overwrite", "Restore files over the originals", 60, winmod.Typed[Restore](), restoreParams...),
		entry(tier0, "versions_prune_preview", "Preview which versions would be removed", 60, winmod.Typed[PrunePreview](),
			prune),
		entry(tier3, "versions_prune", "Remove old backup versions", 300, winmod.Typed[Pruned](),
			device(), prune, winmod.Param{Name: "expect", Type: winmod.Int, Required: true, Min: 0, Max: 1000}),
		entry(tier3, "feature_install", "Install Windows Server Backup", 600, winmod.Typed[Installed](), device()),
	}
}
