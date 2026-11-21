package host

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// The deployment's .env holds the encryption key and every password: the
// updater reads it, copies it into a new deployment as root's with mode
// 600, and changes only EASYRMM_IMAGE and EASYRMM_VERSION, to the
// manifest's server image.

// maxEnvBytes bounds .env; a real one is a few kilobytes.
const maxEnvBytes = 1 << 20

// envValue is KEY's value in .env data, the last if it is there twice (as
// Compose and setup.sh read it), and "" when it is not there.
func envValue(data []byte, key string) string {
	value := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), key+"="); ok {
			value = v
		}
	}
	return value
}

// setEnv sets KEY in .env data, replacing every line that sets it, or
// adding one.
func setEnv(data []byte, key, value string) ([]byte, error) {
	if strings.ContainsAny(value, "\n\r") {
		return nil, fmt.Errorf("a value for %s with a line break", key)
	}
	var out bytes.Buffer
	set := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, key+"=") {
			if set {
				continue
			}
			line, set = key+"="+value, true
		}
		out.WriteString(line + "\n")
	}
	if !set {
		out.WriteString(key + "=" + value + "\n")
	}
	return out.Bytes(), nil
}

// hasProfile reports whether .env's COMPOSE_PROFILES lists profile.
func hasProfile(data []byte, profile string) bool {
	for _, p := range strings.Split(envValue(data, "COMPOSE_PROFILES"), ",") {
		if strings.TrimSpace(p) == profile {
			return true
		}
	}
	return false
}
