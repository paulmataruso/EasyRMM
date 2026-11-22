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
// It reads .env by Compose's rules, in the forms setup.sh writes and reads
// (setup.sh's check_env and env_value read it the same way): blank lines,
// comments, and KEY=value lines, KEY at the start of the line. A value is
// unquoted, ending at a " #" that starts a comment, the blanks around it
// trimmed; or in single or double quotes, which end on the same line, a
// backslash escaping the character after it, and nothing but blanks and a
// comment after them. checkEnv refuses what Compose would read otherwise
// (export, spaces around the key, a quoted value over more lines, text after
// the closing quote, control characters), and settings the updater reads or
// writes set twice or to anything but a plain value, rather than misread
// them.

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

// composeSetting reports whether key is one of Compose's own settings that
// the updater refuses in .env: every COMPOSE_ one but COMPOSE_PROFILES,
// which setup.sh writes. Among them are COMPOSE_FILE, COMPOSE_ENV_FILES
// and COMPOSE_PROJECT_NAME, which change the files Compose reads or its
// project; the updater backs up, restores and starts the deployment as its
// docker-compose.yml says.
func composeSetting(key string) bool {
	return strings.HasPrefix(key, "COMPOSE_") && key != "COMPOSE_PROFILES"
}

var (
	envBlankRE  = regexp.MustCompile(`^[ \t]*(#.*)?$`)
	envKeyRE    = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)=[ \t]*(.*)$`)
	envQuotedRE = regexp.MustCompile(`^(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')[ \t]*(?:#.*)?$`)
	envPlainRE  = regexp.MustCompile(`^[A-Za-z0-9_./:@,+-]*$`)
	// Compose takes these, at a value's start, for blanks before it.
	envOddBlanks = []string{"\u0085", "\u00a0"}
)

// envSetting is a line of .env that sets a key.
type envSetting struct {
	line int // from 1
	key  string
	// value is what Compose reads when it is plain (envPlainRE): the quotes
	// taken off a quoted value, the comment and blanks off an unquoted one.
	// Of another, it is that text, which Compose may read otherwise
	// (escapes, ${...}): the updater reads none such.
	value string
}

// parseEnv reads .env data, or says which line it cannot read as Compose
// does.
func parseEnv(data []byte) ([]envSetting, error) {
	var out []envSetting
	for i, line := range envLines(data) {
		n := i + 1
		if strings.ContainsFunc(line, func(r rune) bool { return (r < ' ' && r != '\t') || r == 0x7f }) {
			if strings.HasSuffix(line, "\r") {
				return nil, fmt.Errorf(".env line %d ends in a carriage return (Windows line ends): the updater reads .env with Unix line ends only", n)
			}
			return nil, fmt.Errorf(".env line %d holds a control character", n)
		}
		if envBlankRE.MatchString(line) {
			continue
		}
		m := envKeyRE.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf(".env line %d is not KEY=value at the start of the line: the updater does not read export, spaces around the key or other forms Compose takes", n)
		}
		key, value := m[1], m[2]
		for _, b := range envOddBlanks {
			if strings.HasPrefix(value, b) {
				return nil, fmt.Errorf(".env line %d: %s's value starts with a blank other than a space or a tab", n, key)
			}
		}
		switch {
		case strings.HasPrefix(value, `"`) || strings.HasPrefix(value, "'"):
			q := envQuotedRE.FindStringSubmatch(value)
			if q == nil {
				return nil, fmt.Errorf(".env line %d: %s's quoted value does not end on its line, or text follows its closing quote: write it on one line, its closing quote followed by nothing but a comment", n, key)
			}
			value = q[1] + q[2]
		default:
			value, _, _ = strings.Cut(value, " #")
			value = strings.TrimRight(value, " \t")
		}
		out = append(out, envSetting{line: n, key: key, value: value})
	}
	return out, nil
}

// checkEnv refuses .env data the updater could read otherwise than Compose
// does.
func checkEnv(data []byte) error {
	settings, err := parseEnv(data)
	if err != nil {
		return err
	}
	seen := map[string]int{}
	for _, s := range settings {
		if composeSetting(s.key) {
			return fmt.Errorf(".env line %d sets %s: of Compose's own settings the updater takes COMPOSE_PROFILES alone, since others (COMPOSE_FILE, COMPOSE_ENV_FILES, COMPOSE_PROJECT_NAME) change the files Compose reads or its project, and the updater backs up, restores and starts the deployment as its docker-compose.yml says. Remove it", s.line, s.key)
		}
		if !slices.Contains(envKeysRead, s.key) {
			continue
		}
		if first, ok := seen[s.key]; ok {
			return fmt.Errorf(".env sets %s twice, on lines %d and %d", s.key, first, s.line)
		}
		seen[s.key] = s.line
		if !envPlainRE.MatchString(s.value) {
			return fmt.Errorf(".env line %d: %s's value %q is not plain (letters, digits and ._/:@,+- only), as the updater reads it", s.line, s.key, s.value)
		}
	}
	return nil
}

// envValue is KEY's value in .env data checked by checkEnv (envSetting),
// and "" when it is not there.
func envValue(data []byte, key string) string {
	settings, _ := parseEnv(data)
	value := ""
	for _, s := range settings {
		if s.key == key {
			value = s.value
		}
	}
	return value
}

// setEnv sets KEY in .env data checked by checkEnv, replacing every line
// that sets it, or adding one.
func setEnv(data []byte, key, value string) ([]byte, error) {
	if strings.ContainsAny(value, "\n\r") {
		return nil, fmt.Errorf("a value for %s with a line break", key)
	}
	settings, err := parseEnv(data)
	if err != nil {
		return nil, err
	}
	sets := map[int]bool{}
	for _, s := range settings {
		if s.key == key {
			sets[s.line] = true
		}
	}
	var out bytes.Buffer
	set := false
	for i, line := range envLines(data) {
		if sets[i+1] {
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
