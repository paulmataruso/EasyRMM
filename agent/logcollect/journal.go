package logcollect

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"time"

	"github.com/paulmataruso/easyrmm/internal/logblock"
)

// Sources of the Linux reader.
const (
	SourceJournal = "linux.journal"
	SourceAuth    = "linux.auth"
	SourceAudit   = "linux.audit"
)

// Journal reads systemd's journal through journalctl, which the collector
// runs as its own user with the journal's group (ADR-0060): journalctl finds
// and opens the journal's files itself, which descriptors could not do. It
// starts no other process and passes no user input to it.
type Journal struct {
	// Command is the journalctl binary; default "journalctl".
	Command string
	// Run starts it, replaced by tests: it returns the output and a function
	// that stops the process.
	Run func(ctx context.Context, name string, args ...string) (io.ReadCloser, func() error, error)
}

// Name implements Reader.
func (*Journal) Name() string { return "journal" }

// Read implements Reader. The cursor is journald's own.
func (j *Journal) Read(ctx context.Context, cursor string, since time.Time, limit int) ([]logblock.Event, string, error) {
	cmd := j.Command
	if cmd == "" {
		cmd = "journalctl"
	}
	args := []string{"--output=json", "--no-pager", "--quiet"}
	if cursor != "" {
		args = append(args, "--after-cursor="+cursor)
	} else {
		args = append(args, "--since=@"+strconv.FormatInt(since.Unix(), 10))
	}
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	run := j.Run
	if run == nil {
		run = start
	}
	out, wait, err := run(ctx, cmd, args...)
	if err != nil {
		return nil, cursor, fmt.Errorf("starting journalctl: %w", err)
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var evs []logblock.Event
	next := cursor
	for sc.Scan() {
		e, cur, ok := ParseJournal(sc.Bytes())
		if !ok {
			continue
		}
		evs = append(evs, e)
		next = cur
		if len(evs) >= limit {
			break
		}
	}
	scanErr := sc.Err()
	cancel() // stops journalctl when the limit ended the read early
	_ = out.Close()
	werr := wait()
	if len(evs) == 0 && scanErr == nil && werr != nil && parent.Err() == nil {
		return nil, cursor, fmt.Errorf("journalctl: %w", werr)
	}
	if scanErr != nil && len(evs) == 0 {
		return nil, cursor, scanErr
	}
	return evs, next, nil
}

func start(ctx context.Context, name string, args ...string) (io.ReadCloser, func() error, error) {
	c := exec.CommandContext(ctx, name, args...) //nolint:gosec // journalctl, with arguments built here from a cursor journald made
	out, err := c.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := c.Start(); err != nil {
		return nil, nil, err
	}
	return out, c.Wait, nil
}

// authIdentifiers are the programs whose lines are sign-in events.
var authIdentifiers = map[string]bool{
	"sshd": true, "sudo": true, "su": true, "login": true, "systemd-logind": true,
	"polkitd": true, "passwd": true, "chpasswd": true, "useradd": true, "userdel": true,
	"usermod": true, "groupadd": true, "gdm-password": true, "lightdm": true, "sddm": true,
}

// ParseJournal turns one line of `journalctl --output=json` into an event and
// the line's cursor. It reports false for a line that is not an entry.
func ParseJournal(line []byte) (logblock.Event, string, bool) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(line, &raw) != nil {
		return logblock.Event{}, "", false
	}
	str := func(k string) string {
		v, ok := raw[k]
		if !ok {
			return ""
		}
		var s string
		if json.Unmarshal(v, &s) == nil {
			return s
		}
		var arr []int // a message with bytes journald does not call text
		if json.Unmarshal(v, &arr) == nil {
			return "[binary data, " + strconv.Itoa(len(arr)) + " bytes]"
		}
		return ""
	}
	cursor := str("__CURSOR")
	us, err := strconv.ParseInt(str("__REALTIME_TIMESTAMP"), 10, 64)
	if cursor == "" || err != nil {
		return logblock.Event{}, "", false
	}
	e := logblock.Event{
		Time:    time.UnixMicro(us).UTC(),
		Source:  SourceJournal,
		Message: str("MESSAGE"),
		Level:   journalLevel(str("PRIORITY")),
		Fields:  map[string]string{},
	}
	for field, key := range map[string]string{
		"_SYSTEMD_UNIT": "unit", "SYSLOG_IDENTIFIER": "identifier", "_PID": "pid",
		"_UID": "uid", "_COMM": "comm", "_HOSTNAME": "host", "_TRANSPORT": "transport",
	} {
		if v := str(field); v != "" {
			e.Fields[key] = v
		}
	}
	if id := e.Fields["identifier"]; authIdentifiers[id] || str("SYSLOG_FACILITY") == "4" || str("SYSLOG_FACILITY") == "10" {
		e.Source = SourceAuth
		e.ID = id
	}
	return e, cursor, true
}

func journalLevel(p string) string {
	switch p {
	case "0", "1", "2", "3":
		return "error"
	case "4":
		return "warn"
	case "7":
		return "debug"
	}
	return "info"
}
