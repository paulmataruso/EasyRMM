// Package roles finds which Windows roles and features a computer has
// (ADR-0073). Evaluate is pure: it decides from what Read collected, so the
// rules are tested on Linux with fixtures. Read is Windows code that does
// direct registry and service-control reads and starts no process but one
// child for Defender.
package roles

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Service is what service control says about a service.
type Service int

// Service states. Missing is the zero value: a service that is not
// installed, or one that could not be read.
const (
	Missing Service = iota
	Stopped
	Running
)

// Installed reports whether the service exists.
func (s Service) Installed() bool { return s != Missing }

// Product types, the string at
// HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType.
const (
	ProductClient     = "WinNT"    // a desktop
	ProductServer     = "ServerNT" // a server or a member server
	ProductController = "LanmanNT" // a domain controller
)

// Defender is what Defender's WMI class MSFT_MpComputerStatus said.
type Defender struct {
	// Read is false when the query failed or ran out of time.
	Read bool
	// RunningMode is AMRunningMode: Normal, Passive, EDR Block Mode, ...
	RunningMode string
	Version     string
}

// Inputs is everything Evaluate decides from.
type Inputs struct {
	ProductType string
	// Services by name: NTDS, CertSvc, DNS, DHCPServer, LanmanServer,
	// Spooler, wbengine, WinDefend, fhsvc.
	Services map[string]Service
	// CAConfigured: a key exists under CertSvc\Configuration.
	CAConfigured bool
	// DHCPParameters: the DHCPServer\Parameters key exists.
	DHCPParameters bool
	// Shares counts the shares that are neither administrative nor IPC.
	Shares int
	// PrintShared: the Print$ share exists or a printer carries the shared
	// flag.
	PrintShared bool
	// PrintQueue: a printer queue on a real port (not the PDF, XPS, fax or
	// file ports every server has), shared or not: an installed Print
	// Server role with a printer is the role in use, though nothing is
	// shared yet.
	PrintQueue bool
	Defender   Defender
	// GroupPolicyModule: the GroupPolicy PowerShell module (GPMC) is installed.
	GroupPolicyModule bool
}

// Evaluate returns the roles the inputs show, in the order of
// agentproto.RoleNames. The list is never nil.
func Evaluate(in Inputs) []agentproto.Role {
	server := in.ProductType == ProductServer || in.ProductType == ProductController
	running := func(name string) bool { return in.Services[name] == Running }
	out := []agentproto.Role{}
	add := func(name, state, version string) {
		out = append(out, agentproto.Role{Name: name, State: state, Version: version})
	}
	// A former domain controller keeps NTDS but not the product type.
	if running("NTDS") && in.ProductType == ProductController {
		add(agentproto.RoleADDS, agentproto.RolePresent, "")
	}
	if server && running("CertSvc") && in.CAConfigured {
		add(agentproto.RoleADCS, agentproto.RolePresent, "")
	}
	if server && running("DNS") {
		add(agentproto.RoleDNS, agentproto.RolePresent, "")
	}
	if server && running("DHCPServer") {
		state := agentproto.RolePresent
		if !in.DHCPParameters {
			state = agentproto.RoleUnconfigured
		}
		add(agentproto.RoleDHCP, state, "")
	}
	// A share is the configured file server role.
	if server && running("LanmanServer") && in.Shares > 0 {
		add(agentproto.RoleFileServer, agentproto.RolePresent, "")
	}
	if server && running("Spooler") && (in.PrintShared || in.PrintQueue) {
		add(agentproto.RolePrintServer, agentproto.RolePresent, "")
	}
	switch {
	case server && in.Services["wbengine"].Installed():
		add(agentproto.RoleWindowsBackup, agentproto.RolePresent, "")
	case server:
		add(agentproto.RoleWindowsBackup, agentproto.RoleNotInstalled, "")
	case in.ProductType == ProductClient:
		// wbengine exists on desktops too, so a desktop is told apart by
		// its product type: always reported, with its state from File
		// History.
		state := agentproto.RoleUnconfigured
		if running("fhsvc") {
			state = agentproto.RolePresent
		}
		add(agentproto.RoleWindowsBackup, state, "")
	}
	if in.Services["WinDefend"].Installed() {
		switch d := in.Defender; {
		case !d.Read:
			add(agentproto.RoleDefender, agentproto.RoleUnknown, "")
		case d.RunningMode == "Normal":
			add(agentproto.RoleDefender, agentproto.RolePresent, d.Version)
		default:
			add(agentproto.RoleDefender, agentproto.RolePassive, d.Version)
		}
	}
	// Group Policy is offered on a domain controller that has the tools (ADR-0083).
	if running("NTDS") && in.ProductType == ProductController && in.GroupPolicyModule {
		add(agentproto.RoleGPMC, agentproto.RolePresent, "")
	}
	return out
}

// ParseDefender reads the JSON line the Defender query prints:
// {"AMRunningMode":"Normal","AMProductVersion":"4.18.x"}.
func ParseDefender(b []byte) (Defender, error) {
	var v struct {
		Mode    string `json:"AMRunningMode"`
		Version string `json:"AMProductVersion"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))), &v); err != nil {
		return Defender{}, err
	}
	if v.Mode == "" {
		return Defender{}, errors.New("roles: Defender reported no running mode")
	}
	return Defender{Read: true, RunningMode: v.Mode, Version: v.Version}, nil
}

// virtualPrintPorts are the ports of printers that print to nothing a print
// server serves: the print-to-PDF, XPS and fax queues and a null port.
var virtualPrintPorts = []string{"portprompt:", "nul:", "xpsport:", "shrfax:", "file:", "microsoft.windows.printing.pdf"}

// realPrintPort says whether a port is one a print server's printers use
// rather than one of the virtual ports.
func realPrintPort(port string) bool {
	p := strings.ToLower(strings.TrimSpace(port))
	if p == "" {
		return false
	}
	for _, v := range virtualPrintPorts {
		if strings.HasPrefix(p, v) {
			return false
		}
	}
	return true
}
