package posture

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
)

// The state controls of slices P2 and P3 (ADR-0082). Unlike the hardening
// modules, which say whether a setting is in place, these say what a computer's
// state is now, read from data the server already holds: the volumes the agent
// reported (the keystore) and Defender's status snapshot (the Windows modules).
// They collect nothing.

// The control ids. They differ from the hardening modules "luks", "bitlocker"
// and "defender", which are settings checks, so one gap is not counted twice
// under the same name.
const (
	DiskEncryption = "disk-encryption"
	DefenderHealth = "defender-health"
)

// Defender's thresholds. A signature older than SignatureMaxDays is not in
// place (an out-of-date engine finds nothing new); no scan for ScanMaxDays is
// partly (the protection is on, the computer is not being checked).
const (
	SignatureMaxDays = 7
	ScanMaxDays      = 14
)

// Volume is a volume the agent reported.
type Volume struct {
	Mount  string
	Status string
}

// encryptionState says whether the computer's system volume is encrypted. The
// reported time is when the agent last reported volumes of the platform's kind
// (BitLocker on Windows, LUKS on Linux); nil when it never has. The Windows
// system volume is C:, the Linux one is mounted at /.
func encryptionState(platform string, reported *time.Time, vols []Volume) (state, detail string) {
	if reported == nil {
		return compliance.StateUnknown, "The computer has not reported its encrypted volumes."
	}
	if platform == "windows" {
		for _, v := range vols {
			if strings.EqualFold(strings.TrimRight(v.Mount, `\/`), "C:") {
				switch strings.ToLower(v.Status) {
				case "encrypted":
					return compliance.StateInPlace, ""
				case "encrypting", "encryption paused":
					return compliance.StatePartly, "Encryption of the system volume is not finished."
				}
				return compliance.StateNotInPlace, "The system volume is not encrypted."
			}
		}
		return compliance.StateNotInPlace, "BitLocker is not on the system volume."
	}
	for _, v := range vols {
		if v.Mount == "/" {
			return compliance.StateInPlace, ""
		}
	}
	return compliance.StateNotInPlace, "No encrypted root volume (LUKS)."
}

// defenderStatus is the part of defender.status's result posture reads
// (winmod/defender.Status keeps the whole result).
type defenderStatus struct {
	AntivirusEnabled          *bool  `json:"antivirusEnabled"`
	RealTimeProtectionEnabled *bool  `json:"realTimeProtectionEnabled"`
	RunningMode               string `json:"runningMode"`
	SignatureAgeDays          *int   `json:"signatureAgeDays"`
	QuickScanAgeDays          *int   `json:"quickScanAgeDays"`
	FullScanAgeDays           *int   `json:"fullScanAgeDays"`
}

// defenderState reads a defender.status snapshot. Defender in passive mode is
// not the active antivirus, so the control does not apply. A snapshot it
// cannot read, or one that does not say whether real-time protection is on,
// is unknown, never a pass.
func defenderState(data []byte) (state, detail string) {
	var st defenderStatus
	if err := json.Unmarshal(data, &st); err != nil {
		return compliance.StateUnknown, "Defender's status could not be read."
	}
	if strings.Contains(strings.ToLower(st.RunningMode), "passive") {
		return compliance.StateNotApplicable, "Defender runs in passive mode."
	}
	var gaps, partial []string
	switch {
	case st.RealTimeProtectionEnabled == nil:
		return compliance.StateUnknown, "Defender does not say whether real-time protection is on."
	case !*st.RealTimeProtectionEnabled:
		gaps = append(gaps, "Real-time protection is off.")
	}
	if st.AntivirusEnabled != nil && !*st.AntivirusEnabled {
		gaps = append(gaps, "Antivirus is off.")
	}
	if st.SignatureAgeDays != nil && *st.SignatureAgeDays >= SignatureMaxDays {
		gaps = append(gaps, fmt.Sprintf("Signatures are %d days old.", *st.SignatureAgeDays))
	}
	if len(gaps) > 0 {
		return compliance.StateNotInPlace, strings.Join(gaps, " ")
	}
	if st.SignatureAgeDays == nil {
		return compliance.StateUnknown, "Defender does not say how old its signatures are."
	}
	scan := st.QuickScanAgeDays
	if st.FullScanAgeDays != nil && (scan == nil || *st.FullScanAgeDays < *scan) {
		scan = st.FullScanAgeDays
	}
	switch {
	case scan == nil:
		partial = append(partial, "No scan is on record.")
	case *scan >= ScanMaxDays:
		partial = append(partial, fmt.Sprintf("The last scan was %d days ago.", *scan))
	}
	if len(partial) > 0 {
		return compliance.StatePartly, strings.Join(partial, " ")
	}
	return compliance.StateInPlace, ""
}
