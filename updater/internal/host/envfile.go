package host

import (
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// The deployment's .env holds the encryption key and every password: the
// updater reads it, copies it into a new deployment as root's with mode
// 600, and changes only EASYRMM_IMAGE and EASYRMM_VERSION, to the
// manifest's server image.
//
// It reads .env as setup.sh writes it: blank lines, comments, and KEY=value
// lines. checkEnv refuses what Compose would read otherwise (export, quoted
// values, spaces around the key, Windows line ends), and settings the
// updater reads or writes set twice or to anything but a plain value,
// rather than misread them.

// maxEnvBytes bounds .env; a real one is a few kilobytes.
const maxEnvBytes = 1 << 20

// envLines splits .env data into its lines. It has no limit on a line's
// length, so no line is lost.
func envLines(data []byte) []string {
	s := strings.TrimSuffix(string(data), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// The settings the updater reads or writes.
var envKeysRead = []string{"EASYRMM_DATA_ROOT", "EASYRMM_IMAGE", "EASYRMM_VERSION", "COMPOSE_PROFILES"}

var (
	envKeyRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
	envPlainRE = regexp.MustCompile(`^[A-Za-z0-9_./:@,+-]*$`)
)

// checkEnv refuses .env data the updater could read otherwise than Compose
// does.
func checkEnv(data []byte) error {
	seen := map[string]int{}
	for i, line := range envLines(data) {
		n := i + 1
		switch {
		case strings.Contains(line, "\r"):
			return fmt.Errorf(".env line %d ends in a carriage return (Windows line ends): the updater reads .env with Unix line ends only", n)
		case strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#"):
			continue
		case !envKeyRE.MatchString(line):
			return fmt.Errorf(".env line %d is not KEY=value at the start of the line: the updater does not read export, spaces around the key or other forms Compose takes", n)
		}
		key, value, _ := strings.Cut(line, "=")
		if strings.HasPrefix(value, `"`) || strings.HasPrefix(value, "'") {
			return fmt.Errorf(".env line %d: %s's value is quoted, which the updater does not read as Compose does: write it unquoted", n, key)
		}
		if !slices.Contains(envKeysRead, key) {
			continue
		}
		if first, ok := seen[key]; ok {
			return fmt.Errorf(".env sets %s twice, on lines %d and %d", key, first, n)
		}
		seen[key] = n
		if !envPlainRE.MatchString(value) {
			return fmt.Errorf(".env line %d: %s's value %q is not plain (letters, digits and ._/:@,+- only), as the updater reads it", n, key, value)
		}
	}
	return nil
}

// envValue is KEY's value in .env data checked by checkEnv, and "" when it
// is not there.
func envValue(data []byte, key string) string {
	value := ""
	for _, line := range envLines(data) {
		if v, ok := strings.CutPrefix(line, key+"="); ok {
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
	for _, line := range envLines(data) {
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
