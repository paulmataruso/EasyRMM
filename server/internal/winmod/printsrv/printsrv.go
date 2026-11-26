// Package printsrv is the catalog of ADR-0076's print-server module:
// printers, queues and jobs, ports and drivers, and the Point and Print
// hardening state. Drivers and ports are read-only except for the named
// actions below; no action installs a driver from a file, share or the
// internet, and the one registry write (point_and_print_restrict) can only
// strengthen the setting.
//
// Tier 3 actions (clearing a queue, removing a printer or a driver, adding a
// driver, restarting the spooler) need print.destroy and a step-up. Document
// names, owners and client computers are a separate action
// (job_list_sensitive), opened by print.view_sensitive.
package printsrv

import (
	"embed"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
	"github.com/paulmataruso/easyrmm/server/internal/winmod/rolekit"
)

//go:embed scripts/*.ps1
var scriptFS embed.FS

// Tiers (ADR-0076, section 2).
const (
	tier0 = iota
	tier1
	tier2
	tier3
)

// Status is print.status's result.
type Status struct {
	ServiceState     string `json:"serviceState"`
	PrinterCount     int    `json:"printerCount"`
	SharedCount      int    `json:"sharedCount"`
	JobCount         int    `json:"jobCount"`
	DomainController bool   `json:"domainController"`
}

// Printer is one printer with its queue summary.
type Printer struct {
	Name                string `json:"name"`
	Driver              string `json:"driver"`
	Port                string `json:"port"`
	Shared              bool   `json:"shared"`
	ShareName           string `json:"shareName"`
	Published           bool   `json:"published"`
	Status              string `json:"status"`
	Paused              bool   `json:"paused"`
	Offline             bool   `json:"offline"`
	IsDefault           bool   `json:"isDefault"`
	JobCount            int    `json:"jobCount"`
	JobsInError         int    `json:"jobsInError"`
	OldestJobAgeMinutes *int64 `json:"oldestJobAgeMinutes"`
}

// Printers is printer_list's result.
type Printers struct {
	Printers  []Printer `json:"printers"`
	Truncated bool      `json:"truncated"`
}

// Port is one printer port.
type Port struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	PortNumber  int64  `json:"portNumber"`
	Description string `json:"description"`
}

// Ports is port_list's result.
type Ports struct {
	Ports     []Port `json:"ports"`
	Truncated bool   `json:"truncated"`
}

// Driver is one installed printer driver.
type Driver struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Manufacturer string `json:"manufacturer"`
	Environment  string `json:"environment"`
	Inbox        bool   `json:"inbox"`
}

// Drivers is driver_list's result.
type Drivers struct {
	Drivers   []Driver `json:"drivers"`
	Truncated bool     `json:"truncated"`
}

// Job is one print job without what names people or files.
type Job struct {
	ID         int64      `json:"id"`
	Status     string     `json:"status"`
	SizeBytes  int64      `json:"sizeBytes"`
	Pages      int64      `json:"pages"`
	Submitted  *time.Time `json:"submitted"`
	AgeMinutes *int64     `json:"ageMinutes"`
}

// Jobs is job_list's result.
type Jobs struct {
	Printer string `json:"printer"`
	Jobs    []Job  `json:"jobs"`
	Total   int    `json:"total"`
}

// JobDoc is what names a job's document, owner and client computer.
type JobDoc struct {
	ID       int64  `json:"id"`
	Document string `json:"document"`
	Owner    string `json:"owner"`
	Client   string `json:"client"`
}

// JobDocs is job_list_sensitive's result.
type JobDocs struct {
	Jobs []JobDoc `json:"jobs"`
}

// Hardening is the Point and Print state (MSRC CVE-2021-34527, KB5005652). The
// numbers are the registry values, null when not set.
type Hardening struct {
	RestrictDriverInstall *int64 `json:"restrictDriverInstall"`
	NoWarningNoElevation  *int64 `json:"noWarningNoElevation"`
	UpdatePromptSettings  *int64 `json:"updatePromptSettings"`
	Weakened              bool   `json:"weakened"`
	SpoolerRunning        bool   `json:"spoolerRunning"`
	DomainController      bool   `json:"domainController"`
}

// Count is the result of a change: how many objects it changed.
type Count struct {
	Count int `json:"count"`
}

var (
	// namePattern suits a printer, driver or port name: letters, digits,
	// spaces and . _ - @ $ ' ( ) # + , & (no backslash: remote connections
	// are not managed here).
	namePattern  = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._\-@$'()#+,&]*$`)
	sharePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$`)
	idsPattern   = regexp.MustCompile(`^\d{1,9}(,\d{1,9}){0,49}$`)
)

func device() winmod.Param {
	return winmod.Param{Name: "device", Type: winmod.Name, Required: true, Max: 64}
}

func nameParam(name string, required bool) winmod.Param {
	return winmod.Param{Name: name, Type: winmod.Text, Required: required, Max: 100, Pattern: namePattern}
}

func printer() winmod.Param { return nameParam("printer", true) }

func ids() winmod.Param {
	return winmod.Param{Name: "ids", Type: winmod.Text, Required: true, Max: 520, Pattern: idsPattern}
}

func library(file string) string {
	b, err := scriptFS.ReadFile("scripts/" + file)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// Script is the text of an action's script as the agent receives it.
func Script(file string) string {
	return strings.Replace(library(file+".ps1"), "#@library common\n", library("_common.ps1"), 1)
}

func entry(tier int, file, label string, timeout int, decode func(json.RawMessage) (json.RawMessage, error), params ...winmod.Param) winmod.Action {
	a := winmod.Action{
		Module: modules.Print, Name: "print." + file, Label: label, Version: 1,
		Script: Script(file), ScriptSHA256: pins[file], Params: params, Timeout: timeout, Decode: decode,
	}
	switch tier {
	case tier0:
		a.Permission, a.Keep = rbac.PermPrintView, time.Hour
	case tier1:
		a.Permission, a.Keep, a.Changes = rbac.PermPrintManage, 7*24*time.Hour, true
	case tier2:
		a.Permission, a.Keep, a.Changes = rbac.PermPrintManage, 7*24*time.Hour, true
		a.Confirm, a.Subject, a.SubjectIsDeviceName = true, "device", true
	case tier3:
		// print.destroy is held by Site Administrators and above, who hold
		// print.manage too: one permission says "manage and destroy".
		a.Permission, a.Keep, a.Changes = rbac.PermPrintDestroy, 7*24*time.Hour, true
		a.Destructive, a.Subject, a.SubjectIsDeviceName = true, "device", true
	}
	return a
}

func portGuard(p map[string]any) error {
	addr := rolekit.Str(p, "address")
	if !rolekit.IPv4(addr) && !rolekit.IPv6(addr) {
		return rolekit.Invalid("address", "Give the printer's IP address.")
	}
	return nil
}

// Actions are the print-server actions the server can run.
func Actions() []winmod.Action {
	scheduled := func(a winmod.Action) winmod.Action {
		a.Freshness, a.Schedule = 5*time.Minute, time.Hour
		return a
	}
	docs := entry(tier0, "job_list_sensitive", "Read the documents, owners and client computers of print jobs", 60, winmod.Typed[JobDocs](), printer())
	docs.Permission, docs.Sensitive, docs.SensitivePermission, docs.Keep = rbac.PermPrintViewSensitive, true, rbac.PermPrintViewSensitive, 15*time.Minute
	docs.CountField = "jobs"
	jobs := entry(tier0, "job_list", "List the jobs of a printer", 60, winmod.Typed[Jobs](), printer())
	jobs.CountField = "jobs"
	printers := scheduled(entry(tier0, "printer_list", "List the printers", 60, winmod.Typed[Printers]()))
	printers.CountField = "printers"

	set := entry(tier2, "printer_set", "Change a printer", 60, winmod.Typed[Count](), device(), printer(),
		winmod.Param{Name: "comment", Type: winmod.Text, Max: 256},
		winmod.Param{Name: "location", Type: winmod.Text, Max: 256},
		winmod.Param{Name: "shared", Type: winmod.Bool},
		winmod.Param{Name: "shareName", Type: winmod.Text, Max: 80, Pattern: sharePattern},
		winmod.Param{Name: "published", Type: winmod.Bool})
	port := entry(tier2, "port_add", "Add a TCP/IP printer port", 30, winmod.Typed[Count](), device(), nameParam("name", true),
		winmod.Param{Name: "address", Type: winmod.Text, Required: true, Max: 45},
		winmod.Param{Name: "port", Type: winmod.Int, Required: true, Min: 1, Max: 65535})
	port.Guard = portGuard

	return []winmod.Action{
		scheduled(entry(tier0, "status", "Read the print server state", 60, winmod.Typed[Status]())),
		printers,
		entry(tier0, "port_list", "List the printer ports", 60, winmod.Typed[Ports]()),
		entry(tier0, "driver_list", "List the printer drivers", 60, winmod.Typed[Drivers]()),
		jobs, docs,
		scheduled(entry(tier0, "hardening_status", "Read the Point and Print state", 30, winmod.Typed[Hardening]())),
		entry(tier1, "job_cancel", "Cancel print jobs", 60, winmod.Typed[Count](), printer(), ids()),
		entry(tier1, "job_pause", "Pause print jobs", 60, winmod.Typed[Count](), printer(), ids()),
		entry(tier1, "job_resume", "Resume print jobs", 60, winmod.Typed[Count](), printer(), ids()),
		entry(tier1, "job_restart", "Restart print jobs", 60, winmod.Typed[Count](), printer(), ids()),
		entry(tier1, "printer_pause", "Pause a printer", 30, winmod.Typed[Count](), printer()),
		entry(tier1, "printer_resume", "Resume a printer", 30, winmod.Typed[Count](), printer()),
		set,
		entry(tier2, "printer_add", "Add a printer (an installed driver, an existing port)", 60, winmod.Typed[Count](),
			device(), nameParam("name", true), nameParam("driverName", true), nameParam("portName", true)),
		port,
		entry(tier2, "port_remove", "Remove a printer port no printer uses", 30, winmod.Typed[Count](), device(), nameParam("name", true)),
		entry(tier2, "point_and_print_restrict", "Restrict driver installation to administrators", 30, winmod.Typed[Hardening](), device()),
		entry(tier3, "spooler_restart", "Restart the Print Spooler", 90, winmod.Typed[Count](), device()),
		entry(tier3, "queue_clear", "Cancel every job of a printer", 120, winmod.Typed[Count](), device(), printer()),
		entry(tier3, "printer_remove", "Remove a printer and its share", 60, winmod.Typed[Count](), device(), printer()),
		entry(tier3, "driver_add", "Add a driver from the driver store", 120, winmod.Typed[Count](), device(), nameParam("name", true)),
		entry(tier3, "driver_remove", "Remove a printer driver", 60, winmod.Typed[Count](), device(), nameParam("name", true)),
	}
}
