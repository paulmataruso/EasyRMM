// Package bitlocker is the catalog of ADR-0081's BitLocker actions. Today it
// has one, enable, and it is a native action: agent Go code does the work,
// because the recovery password it creates must pass from the computer to the
// escrow route without a script's output, a transcript or a pipe ever holding
// it. The catalog entry, permission, step-up, typed confirmation and audit are
// the framework's, as for any action (ADR-0073).
package bitlocker

import (
	"encoding/json"
	"regexp"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
	"github.com/paulmataruso/easyrmm/server/internal/winmod"
)

// Handler is the name of the agent's native handler for enable.
const Handler = "bitlocker.enable"

// Encryption modes of enable.
const (
	UsedSpace = "used_space"
	Full      = "full"
)

// Enable is enable's result. It holds no key; the escrow state is the one the
// server reported for the recovery password before encryption started.
type Enable struct {
	Volume string `json:"volume"`
	// Escrow is "verified": the agent starts nothing earlier.
	Escrow string `json:"escrow"`
	// Encryption is "started" or "already_on".
	Encryption string `json:"encryption"`
	// Mode is the encryption mode used.
	Mode string `json:"mode"`
}

var volumePattern = regexp.MustCompile(`^[A-Za-z]:$`)

// Actions are the BitLocker actions the server can run.
func Actions() []winmod.Action {
	return []winmod.Action{{
		Module: modules.BitLocker, Name: "bitlocker.enable", Label: "Turn on BitLocker", Version: 1,
		Native: Handler,
		Params: []winmod.Param{
			// The confirmation: the computer's name, compared with the real one.
			{Name: "computer", Type: winmod.Name, Required: true, Max: 253},
			{Name: "volume", Type: winmod.Text, Required: true, Max: 2, Pattern: volumePattern},
			{Name: "encryption", Type: winmod.Enum, Values: []string{UsedSpace, Full}},
		},
		Permission: rbac.PermBitLockerManage,
		// Changing a customer's computer: the typed name and a step-up.
		Destructive: true, Subject: "computer", SubjectIsDeviceName: true,
		// The agent waits for the escrow to verify before it encrypts.
		Timeout: 900, Keep: 7 * 24 * time.Hour, Changes: true, NeedsEscrow: true,
		Decode: winmod.Typed[Enable](),
	}}
}

// Raw is Enable as JSON, for tests.
func Raw(e Enable) json.RawMessage {
	b, _ := json.Marshal(e)
	return b
}
