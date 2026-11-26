package agentproto

import (
	"encoding/json"
	"strings"
)

// Native handlers (ADR-0073 as amended by ADR-0081): a job of shell ShellNative
// names one of these in its Script. The agent runs only handlers it was built
// with and answers with the same one result line a script prints, so the
// server records it as it records any action's.
const (
	// NativeBitLockerEnable turns BitLocker on through the verified-escrow
	// gate: the recovery password is escrowed and verified before encryption
	// starts.
	NativeBitLockerEnable = "bitlocker.enable"
	// NativeBitLockerEnableVersion is the action's version, which the result
	// line carries and the server checks.
	NativeBitLockerEnableVersion = 1
)

// NativeResultPrefix starts the last line of a native handler's output (the
// winmod framework's, ADR-0073).
const NativeResultPrefix = "EASYRMM-WINMOD-RESULT-V1 "

// BitLockerEnableParams are the parameters of NativeBitLockerEnable.
type BitLockerEnableParams struct {
	// Computer is the computer's name, confirmed by the person; the server
	// compared it with the real one and the agent compares it again.
	Computer string `json:"computer"`
	// Volume is the drive letter with its colon, such as "C:".
	Volume string `json:"volume"`
	// Encryption is "used_space" (the default) or "full".
	Encryption string `json:"encryption,omitempty"`
}

// BitLockerEnableResult is the data of a successful NativeBitLockerEnable.
type BitLockerEnableResult struct {
	Volume     string `json:"volume"`
	Escrow     string `json:"escrow"`
	Encryption string `json:"encryption"`
	Mode       string `json:"mode"`
}

// NativeResult is the one result line of a native handler: ok with data, or
// not ok with a short code and a message. It never carries a secret.
func NativeResult(version int, data any, code, message string) string {
	env := map[string]any{"ok": code == "", "version": version}
	if code == "" {
		env["data"] = data
	} else {
		msg := []rune(message)
		if len(msg) > 400 {
			msg = msg[:400]
		}
		env["error"] = map[string]string{"code": code, "message": strings.TrimSpace(string(msg))}
	}
	b, err := json.Marshal(env)
	if err != nil {
		b = []byte(`{"ok":false,"version":` + "0" + `,"error":{"code":"internal","message":"The result could not be written."}}`)
	}
	return NativeResultPrefix + string(b) + "\n"
}
