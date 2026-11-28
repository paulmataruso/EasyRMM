// Package settings is the agent's side of signed settings (ADR-0058): its own
// catalog of the keys its build understands, and the verify, check, save
// and apply of the document the server sends in a heartbeat answer.
//
// The agent verifies a document once, when it arrives, and keeps what it
// applied in settings.json; a restart applies the saved document before the
// first heartbeat, a rotation of the job key never makes it unreadable, and
// one saved for another device is never applied. A key the document omits, or
// the agent never received a document for, takes the built-in default: what
// the agent did before the key existed.
package settings

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"sync"

	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// HeartbeatKey is the interval the agent checks in at.
const HeartbeatKey = "agent.heartbeat_seconds"

// Bounds of the heartbeat key in this build's schema (version 1).
const (
	minHeartbeat = agentproto.MinSettingsHeartbeat
	maxHeartbeat = 300
)

// entry is one key of the agent's catalog. judge reads a value under this
// build's schema: the value to keep, and "" when it is as sent,
// agentproto.ProblemClamped when it was brought within bounds, or
// agentproto.ProblemInvalid (no value) when the schema does not allow it.
// The built-in default is not a value here: it is what the code does where
// the key is absent (Interval).
type entry struct {
	// version is the version of the key's schema; it rises whenever the key
	// accepts more, never less.
	version int
	judge   func(json.RawMessage) (json.RawMessage, string)
}

// catalog lists the keys this build understands. A key without an effect in
// the agent is not added.
var catalog = map[string]entry{
	HeartbeatKey: {version: 1, judge: judgeInt(minHeartbeat, maxHeartbeat)},
}

// judgeInt accepts a JSON whole number, and brings one out of bounds within
// them.
func judgeInt(lo, hi int) func(json.RawMessage) (json.RawMessage, string) {
	return func(raw json.RawMessage) (json.RawMessage, string) {
		n, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
		if err != nil {
			return nil, agentproto.ProblemInvalid
		}
		switch {
		case n < int64(lo):
			return json.RawMessage(strconv.Itoa(lo)), agentproto.ProblemClamped
		case n > int64(hi):
			return json.RawMessage(strconv.Itoa(hi)), agentproto.ProblemClamped
		}
		return json.RawMessage(strconv.FormatInt(n, 10)), ""
	}
}

// Capabilities is what the agent announces in its heartbeat: that it takes
// settings documents, and each key it understands with its schema's version.
func Capabilities() *agentproto.SettingsCapabilities {
	c := &agentproto.SettingsCapabilities{Accepts: []string{agentproto.CapSettings}, Settings: map[string]int{}}
	for k, e := range catalog {
		c.Settings[k] = e.version
	}
	return c
}

// Store is where the agent keeps its settings (state.Store).
type Store interface {
	LoadSettings() *state.Settings
	SaveSettings(state.Settings) error
}

// Agent holds the settings applied and handles the documents of heartbeat
// answers.
type Agent struct {
	// DeviceID is this device's: a document for another is refused, and the
	// saved one applies only if it names this device.
	DeviceID string
	// Keys returns the job-signing keys the agent trusts, nil while none is
	// pinned: an agent that has pinned none refuses every document.
	Keys  func() agentproto.Keys
	Store Store
	Log   *slog.Logger
	// Record is told of each document accepted (the instruction log); nil
	// records nothing.
	Record agentproto.InstructionRecorder

	mu       sync.Mutex
	version  int64
	hash     string
	values   map[string]json.RawMessage
	problems map[string]string
}

// Load applies the saved settings, before the first heartbeat. Settings
// saved for another device, or damaged, are ignored: the agent starts from its
// built-in defaults. The saved document is not verified again (it was, when
// it arrived); each key is judged against this build's catalog, so a build
// moved back to an older one applies the keys it knows and takes defaults for
// the rest.
func (a *Agent) Load() {
	st := a.Store.LoadSettings()
	if st == nil {
		return
	}
	p, err := decode(st.Document)
	if err != nil || p.DeviceID != a.DeviceID || p.Version < 1 || p.Version > agentproto.MaxSettingsVersion {
		a.Log.Warn("the saved settings are not for this device or are damaged; the built-in defaults apply")
		return
	}
	values, problems := judge(p.Settings, st.Applied)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.version, a.hash, a.values, a.problems = p.Version, agentproto.SettingsHash(p.Settings), values, problems
}

// decode reads a stored document's payload without checking its signature.
func decode(s agentproto.SignedSettings) (agentproto.SettingsPayload, error) {
	var p agentproto.SettingsPayload
	b, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return p, err
	}
	return p, json.Unmarshal(b, &p)
}

// judge applies the catalog to a document's keys: the values to hold and the
// problems to report. A key that is invalid keeps the value it had (prev),
// judged again under this build's schema; a key this build does not know is
// left out, so its built-in default applies.
func judge(doc, prev map[string]json.RawMessage) (map[string]json.RawMessage, map[string]string) {
	values := map[string]json.RawMessage{}
	problems := map[string]string{}
	for k, raw := range doc {
		e, ok := catalog[k]
		if !ok {
			continue
		}
		v, p := e.judge(raw)
		if p == agentproto.ProblemInvalid {
			problems[k] = p
			if old, ok := prev[k]; ok {
				if v, p2 := e.judge(old); p2 != agentproto.ProblemInvalid {
					values[k] = v
				}
			}
			continue
		}
		values[k] = v
		if p != "" {
			problems[k] = p
		}
	}
	return values, problems
}

// Capabilities is what the agent announces in its heartbeat (see the
// package function).
func (a *Agent) Capabilities() *agentproto.SettingsCapabilities { return Capabilities() }

// Report is what the agent holds, for its next heartbeat.
func (a *Agent) Report() *agentproto.SettingsReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := &agentproto.SettingsReport{Version: a.version}
	if len(a.problems) > 0 {
		r.Problems = make(map[string]string, len(a.problems))
		for k, v := range a.problems {
			r.Problems[k] = v
		}
	}
	return r
}

// Interval is the heartbeat interval the agent uses, in seconds, given the
// answer's heartbeatSeconds. With no value held it is the answer's, as the
// agent always did (the caller bounds it); with one, the shorter of the two,
// never below the catalog's minimum, so a server that no longer sends
// documents (a rollback) still sees the device within its own window.
func (a *Agent) Interval(answered int) (seconds int, held bool) {
	a.mu.Lock()
	raw, ok := a.values[HeartbeatKey]
	a.mu.Unlock()
	if !ok {
		return answered, false
	}
	n, err := strconv.Atoi(string(raw))
	if err != nil {
		return answered, false
	}
	if answered > 0 {
		n = min(n, answered)
	}
	return max(n, minHeartbeat), true
}

// Answered handles the document of a heartbeat answer, nil when it carried
// none, and the server's protocol level. It returns true when what the agent
// reports changed (a document applied or refused), so that the next heartbeat
// comes soon and the console shows the result promptly.
func (a *Agent) Answered(level int, s *agentproto.SignedSettings) bool {
	if s == nil {
		return false
	}
	if level < 2 {
		return a.refuse(errors.New("the server does not speak protocol level 2"))
	}
	keys := a.Keys()
	p, err := agentproto.VerifySettings(keys, *s, a.DeviceID)
	if err != nil {
		return a.refuse(err)
	}
	hash := agentproto.SettingsHash(p.Settings)
	a.mu.Lock()
	held, heldHash, prev := a.version, a.hash, a.values
	a.mu.Unlock()
	switch {
	case p.Version < held:
		return a.refuse(fmt.Errorf("version %d is older than the %d applied", p.Version, held))
	case p.Version == held:
		if hash == heldHash {
			return false // the same document again changes nothing
		}
		return a.refuse(fmt.Errorf("version %d again with other content", p.Version))
	}
	// Every key must be one the agent reported: nothing in a document is
	// unknown to it (ADR-0009), and one that is means a bug.
	for _, k := range sortedNames(p.Settings) {
		if _, ok := catalog[k]; !ok {
			return a.refuse(fmt.Errorf("key %s was not reported", k))
		}
	}
	values, problems := judge(p.Settings, prev)
	if err := a.Store.SaveSettings(state.Settings{Document: *s, Applied: values}); err != nil {
		return a.refuse(fmt.Errorf("could not save: %w", err))
	}
	a.mu.Lock()
	a.version, a.hash, a.values, a.problems = p.Version, hash, values, problems
	a.mu.Unlock()
	for _, k := range sortedNames(problems) {
		a.Log.Warn("a setting in the server's document was not applied as sent", "key", k, "problem", problems[k])
	}
	if a.Record != nil {
		a.Record(agentproto.InstructionSettings, strconv.FormatInt(p.Version, 10), keys.SignerOf(func(k ed25519.PublicKey) bool {
			_, err := agentproto.VerifySettings(agentproto.Keys{k}, *s, a.DeviceID)
			return err == nil
		}))
	}
	a.Log.Info("applied the server's settings", "version", p.Version)
	return true
}

// refuse keeps the settings held and reports the refusal, its reason naming
// the field or key; it returns true, since the report changed. The held keys'
// own problems stay.
func (a *Agent) refuse(err error) bool {
	a.Log.Error("refused the server's settings document", "error", err)
	reason := err.Error()
	if room := agentproto.MaxSettingsReason - len(agentproto.ProblemRefused) - 2; len(reason) > room {
		reason = reason[:room]
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	problems := map[string]string{}
	for k, v := range a.problems {
		if k != agentproto.SettingsDocumentKey {
			problems[k] = v
		}
	}
	problems[agentproto.SettingsDocumentKey] = agentproto.ProblemRefused + ": " + reason
	a.problems = problems
	return true
}

func sortedNames[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
