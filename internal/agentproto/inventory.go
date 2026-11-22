package agentproto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Inventory and telemetry (ADR-0018).
const (
	// PathInventory receives a device's inventory.
	PathInventory = "/api/agent/v1/inventory"
	// MaxInventoryBody is the largest inventory body the server reads.
	MaxInventoryBody = 4 << 20
	// MaxPackages is the most packages an inventory lists.
	MaxPackages = 20000
	// MaxListed is the most disks, interfaces or filesystems a report lists.
	MaxListed = 64
	// MaxAddresses is the most addresses one interface lists.
	MaxAddresses = 32
)

// Inventory describes a device's hardware, operating system, network and
// installed software. Lists are sorted so an unchanged machine produces an
// identical document and hash.
type Inventory struct {
	System     SystemInfo  `json:"system"`
	CPU        CPUInfo     `json:"cpu"`
	Memory     uint64      `json:"memoryBytes"`
	OS         OSInfo      `json:"os"`
	Disks      []Disk      `json:"disks"`
	Interfaces []Interface `json:"interfaces"`
	Gateways   []string    `json:"gateways"`
	DNS        []string    `json:"dnsServers"`
	// PackageManager is where Packages came from: dpkg, rpm, apk, pacman,
	// windows (the programs Windows lists as installed), or empty when none
	// was found.
	PackageManager string    `json:"packageManager"`
	Packages       []Package `json:"packages"`
	// EasyPatch is what the device's EasyPatch agent says about itself
	// (ADR-0030); nil when it is not installed.
	EasyPatch *EasyPatchAgent `json:"easyPatch,omitempty"`
	// PowerShell lists Windows PowerShell and the PowerShell 7 installs
	// the agent found, usable or not (ADR-0064), at most MaxPowerShell;
	// nil (absent) on Linux and from agents that do not look, empty when
	// none was found. Added after protocol level 2: sent only to a server
	// of level 2 or higher.
	PowerShell []PowerShellInstall `json:"powerShell,omitzero"`
}

// MaxPowerShell is the most PowerShell installs an inventory lists.
const MaxPowerShell = 16

// PowerShellInstall is one PowerShell the agent found on Windows.
type PowerShellInstall struct {
	// Edition is EditionDesktop (Windows PowerShell) or EditionCore.
	Edition string `json:"edition"`
	Version string `json:"version"`
	// Arch is ArchX64, ArchARM64 or ArchX86, empty when unread.
	Arch    string `json:"arch"`
	Path    string `json:"path"`
	Preview bool   `json:"preview,omitempty"`
	// Store says it is a Microsoft Store (MSIX) install, reported and
	// never run.
	Store bool `json:"store,omitempty"`
	// Usable says a pwsh run may choose it; Reason says why it may not,
	// or why it could not be read.
	Usable bool   `json:"usable"`
	Reason string `json:"reason,omitempty"`
	// Blocked says it is not usable although its own files pass: what a
	// run of it would load from outside it, its module folders or its
	// configuration, does not. A run that would have used it fails, and a
	// script that allows Windows PowerShell does not run there instead
	// (ADR-0064). Servers that do not know it ignore it.
	Blocked bool `json:"blocked,omitempty"`
}

// EasyPatchAgent is the EasyPatch agent's own account of its enrollment, from
// its `status --json`. Only what changes with enrollment is kept, so an
// unchanged agent leaves the inventory unchanged.
type EasyPatchAgent struct {
	Version string `json:"version"`
	// Status is the enrollment: Active, PendingApproval, NotEnrolled,
	// Revoked… as EasyPatch names it.
	Status string `json:"status"`
	// ServerURL is the EasyPatch server it is enrolled with, without a
	// trailing slash.
	ServerURL      string `json:"serverUrl"`
	EndpointID     string `json:"endpointId"`
	KeyFingerprint string `json:"keyFingerprint"`
	// Error says why the agent could not report, when it could not.
	Error string `json:"error,omitempty"`
}

// SystemInfo is the machine as its firmware describes it.
type SystemInfo struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	Serial       string `json:"serial"`
	BIOSVendor   string `json:"biosVendor"`
	BIOSVersion  string `json:"biosVersion"`
	BIOSDate     string `json:"biosDate"`
	// Virtualization names the hypervisor or container (kvm, vmware,
	// hyper-v, xen, container…), empty on physical hardware.
	Virtualization string `json:"virtualization"`
}

// CPUInfo describes the processors.
type CPUInfo struct {
	Model   string `json:"model"`
	Sockets int    `json:"sockets"`
	Cores   int    `json:"cores"`   // physical cores, all sockets
	Threads int    `json:"threads"` // logical processors
}

// OSInfo describes the operating system.
type OSInfo struct {
	Name     string `json:"name"`    // "Debian GNU/Linux 13 (trixie)"
	ID       string `json:"id"`      // os-release ID: debian, ubuntu, rhel
	Version  string `json:"version"` // os-release VERSION_ID
	Kernel   string `json:"kernel"`
	Timezone string `json:"timezone"`
}

// Disk is a physical (or virtual) block device.
type Disk struct {
	Name      string `json:"name"` // sda, nvme0n1
	Model     string `json:"model"`
	Serial    string `json:"serial"`
	SizeBytes uint64 `json:"sizeBytes"`
	// Kind is ssd, hdd, nvme or empty when unknown.
	Kind      string `json:"kind"`
	Removable bool   `json:"removable"`
}

// Interface is a network interface other than loopback.
type Interface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses"` // CIDR: 192.0.2.10/24, 2001:db8::1/64
	Up        bool     `json:"up"`
	SpeedMbps int      `json:"speedMbps"` // 0 when unknown
}

// Package is one installed package, or on Windows one installed program.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	// Publisher is the program's publisher on Windows.
	Publisher string `json:"publisher,omitempty"`
}

// Hash identifies an inventory's content: the hex SHA-256 of its JSON.
func (inv *Inventory) Hash() string {
	b, err := json.Marshal(inv)
	if err != nil { // only unsupported values fail, and Inventory has none
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Metrics are a device's measurements at one heartbeat.
type Metrics struct {
	// CPUPercent is processor use since the previous heartbeat, 0–100.
	CPUPercent    float64      `json:"cpuPercent"`
	MemoryTotal   uint64       `json:"memoryTotal"`
	MemoryUsed    uint64       `json:"memoryUsed"`
	SwapTotal     uint64       `json:"swapTotal"`
	SwapUsed      uint64       `json:"swapUsed"`
	Load1         float64      `json:"load1"`
	Load5         float64      `json:"load5"`
	Load15        float64      `json:"load15"`
	UptimeSeconds int64        `json:"uptimeSeconds"`
	Processes     int          `json:"processes"`
	Filesystems   []Filesystem `json:"filesystems"`
}

// Filesystem is a mounted local filesystem and its use.
type Filesystem struct {
	Mount      string `json:"mount"`
	Device     string `json:"device"`
	Type       string `json:"type"`
	TotalBytes uint64 `json:"totalBytes"`
	UsedBytes  uint64 `json:"usedBytes"`
}

// InventoryResponse acknowledges an inventory.
type InventoryResponse struct {
	Hash string `json:"hash"`
}
