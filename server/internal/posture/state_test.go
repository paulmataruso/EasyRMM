package posture

import (
	"testing"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/compliance"
)

func TestEncryptionState(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		platform string
		reported *time.Time
		vols     []Volume
		want     string
	}{
		{"never reported", "linux", nil, nil, compliance.StateUnknown},
		{"linux, reported none", "linux", &now, nil, compliance.StateNotInPlace},
		{"linux, only /boot", "linux", &now, []Volume{{Mount: "/boot", Status: "luks2"}}, compliance.StateNotInPlace},
		{"linux, encrypted root", "linux", &now, []Volume{{Mount: "/boot", Status: "luks2"}, {Mount: "/", Status: "luks2"}}, compliance.StateInPlace},
		{"windows, reported none", "windows", &now, nil, compliance.StateNotInPlace},
		{"windows, C encrypted", "windows", &now, []Volume{{Mount: "C:", Status: "encrypted"}}, compliance.StateInPlace},
		{"windows, lower case with slash", "windows", &now, []Volume{{Mount: `c:\`, Status: "Encrypted"}}, compliance.StateInPlace},
		{"windows, C encrypting", "windows", &now, []Volume{{Mount: "C:", Status: "encrypting"}}, compliance.StatePartly},
		{"windows, C decrypted", "windows", &now, []Volume{{Mount: "C:", Status: "decrypted"}}, compliance.StateNotInPlace},
		{"windows, only D encrypted", "windows", &now, []Volume{{Mount: "D:", Status: "encrypted"}}, compliance.StateNotInPlace},
	}
	for _, c := range cases {
		if got, detail := encryptionState(c.platform, c.reported, c.vols); got != c.want || (got != compliance.StateInPlace && detail == "") {
			t.Errorf("%s: %s (%q), want %s with a reason", c.name, got, detail, c.want)
		}
	}
}

func TestDefenderState(t *testing.T) {
	cases := []struct{ name, data, want string }{
		{"all good", `{"realTimeProtectionEnabled":true,"antivirusEnabled":true,"runningMode":"Normal","signatureAgeDays":1,"quickScanAgeDays":2}`, compliance.StateInPlace},
		{"full scan is recent enough", `{"realTimeProtectionEnabled":true,"signatureAgeDays":0,"quickScanAgeDays":40,"fullScanAgeDays":3}`, compliance.StateInPlace},
		{"real-time off", `{"realTimeProtectionEnabled":false,"signatureAgeDays":1,"quickScanAgeDays":1}`, compliance.StateNotInPlace},
		{"antivirus off", `{"realTimeProtectionEnabled":true,"antivirusEnabled":false,"signatureAgeDays":1,"quickScanAgeDays":1}`, compliance.StateNotInPlace},
		{"old signatures", `{"realTimeProtectionEnabled":true,"signatureAgeDays":7,"quickScanAgeDays":1}`, compliance.StateNotInPlace},
		{"old scan", `{"realTimeProtectionEnabled":true,"signatureAgeDays":1,"quickScanAgeDays":20}`, compliance.StatePartly},
		{"never scanned", `{"realTimeProtectionEnabled":true,"signatureAgeDays":1}`, compliance.StatePartly},
		{"no signature age", `{"realTimeProtectionEnabled":true,"quickScanAgeDays":1}`, compliance.StateUnknown},
		{"real-time not said", `{"signatureAgeDays":1,"quickScanAgeDays":1}`, compliance.StateUnknown},
		{"passive mode", `{"realTimeProtectionEnabled":false,"runningMode":"Passive mode"}`, compliance.StateNotApplicable},
		{"unreadable", `[1]`, compliance.StateUnknown},
	}
	for _, c := range cases {
		if got, detail := defenderState([]byte(c.data)); got != c.want || (got != compliance.StateInPlace && got != compliance.StateNotApplicable && detail == "") {
			t.Errorf("%s: %s (%q), want %s", c.name, got, detail, c.want)
		}
	}
}

func TestStateControlsHaveWeightsAndLabels(t *testing.T) {
	for _, id := range []string{DiskEncryption, DefenderHealth} {
		if weights[id] != 3 || Label(id) == "" || Label(id) == id {
			t.Errorf("%s: weight %d, label %q", id, weights[id], Label(id))
		}
	}
	if volumeKind("windows") != "bitlocker" || volumeKind("linux") != "luks" {
		t.Error("volume kinds")
	}
}
