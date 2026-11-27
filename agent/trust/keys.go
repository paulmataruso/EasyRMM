package trust

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/paulmataruso/easyrmm/agent/state"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// The agent's side of ADR-0057: the server keys it trusts, and the two
// statements that change them. A new key is accepted only through a hand-over
// that verifies under a key already trusted; the others are dropped only
// through a cut-over signed by the key that stays. Nothing else adds a key,
// except `trust-key`, which an administrator runs on the computer itself.

// KeyPersist is where the key store keeps what it changes (state.Store).
type KeyPersist interface {
	SaveConfig(*state.Config) error
	LoadKeyLog() state.KeyLog
	SaveKeyLog(state.KeyLog) error
}

// keepHandledKeys is how many handled statement IDs the agent remembers.
const keepHandledKeys = 16

// TransitionLength is how long the declared key transition lasts after an
// accepted cut-over: the longest anything signed with a dropped key can still
// be on its way.
const TransitionLength = agentproto.KeyStatementValid

// Statement kinds in refusals and the log.
const (
	stmtHandover = agentproto.InstructionHandover
	stmtCutover  = agentproto.InstructionCutover
)

// KeyStore holds the keys the agent trusts. It is safe for concurrent use:
// the job worker, the updater and the channel read it while the heartbeat
// handles statements.
type KeyStore struct {
	// DeviceID and Install bind a statement to this device and this install
	// (agentproto.InstallID of the device's public key).
	DeviceID string
	Install  string
	// Config is the enrollment whose JobKeys the store owns.
	Config *state.Config
	Store  KeyPersist
	Log    *slog.Logger
	// Record is told of each accepted statement (the instruction log); nil
	// records nothing.
	Record agentproto.InstructionRecorder
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu      sync.Mutex
	refusal *agentproto.KeyRefusal
}

func (k *KeyStore) now() time.Time {
	if k.Now != nil {
		return k.Now()
	}
	return time.Now()
}

func (k *KeyStore) logger() *slog.Logger {
	if k.Log != nil {
		return k.Log
	}
	return slog.New(slog.DiscardHandler)
}

// held is the keys a Config holds as trusted, oldest first, the old single
// jobKey field read only when jobKeys does not exist.
func held(c *state.Config) []state.JobKey {
	if len(c.JobKeys) > 0 {
		return c.JobKeys
	}
	if c.JobKey != "" {
		return []state.JobKey{{Key: c.JobKey}}
	}
	return nil
}

func decode(list []state.JobKey) agentproto.Keys {
	out := make(agentproto.Keys, 0, len(list))
	for _, j := range list {
		if pub, err := agentproto.DecodeKey(j.Key); err == nil {
			out = append(out, pub)
		}
	}
	return out
}

// HeldKeys is the keys a configuration trusts, oldest first, for a process
// that holds no store (the uninstaller).
func HeldKeys(c *state.Config) agentproto.Keys { return decode(held(c)) }

// Keys returns the keys the agent trusts, oldest first: nil while none is
// pinned, and an agent that has pinned none refuses every instruction.
func (k *KeyStore) Keys() agentproto.Keys {
	k.mu.Lock()
	defer k.mu.Unlock()
	return decode(held(k.Config))
}

// Dropped returns the keys a cut-over took away, which are never trusted.
func (k *KeyStore) Dropped() agentproto.Keys {
	k.mu.Lock()
	defer k.mu.Unlock()
	return decode(k.Config.DroppedJobKeys)
}

// Report is what heartbeats and job polls carry: each trusted key with its
// generation.
func (k *KeyStore) Report() []agentproto.TrustedKey {
	k.mu.Lock()
	defer k.mu.Unlock()
	list := held(k.Config)
	out := make([]agentproto.TrustedKey, len(list))
	for i, j := range list {
		out[i] = agentproto.TrustedKey{Key: j.Key, Generation: j.Generation}
	}
	return out
}

// Held is a copy of the trusted keys, oldest first, and of the dropped ones.
func (k *KeyStore) Held() (trusted, dropped []state.JobKey) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return slices.Clone(held(k.Config)), slices.Clone(k.Config.DroppedJobKeys)
}

// InTransition reports whether the agent is within the declared key
// transition: from the cut-over it accepted until ten minutes after. It is
// recorded in agent.json, so it holds across a restart.
func (k *KeyStore) InTransition() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.now().Before(k.Config.KeyTransitionUntil)
}

// Caps is what the agent announces in its heartbeat.
func (k *KeyStore) Caps() []string { return []string{agentproto.CapJobKeys} }

// Refusal is the statement the agent last refused, to be reported until an
// answer carries no statement; nil when there is none.
func (k *KeyStore) Refusal() *agentproto.KeyRefusal {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.refusal
}

func (k *KeyStore) refuse(kind string, p agentproto.KeyStatement, reason string) {
	reason = strings.Join(strings.Fields(reason), " ")
	if len(reason) > agentproto.MaxKeyRefusal {
		reason = reason[:agentproto.MaxKeyRefusal]
	}
	k.logger().Warn("refused a job key statement", "statement", kind, "id", p.ID, "reason", reason)
	if p.ID == "" {
		// Nothing to name it by: not echoed.
		return
	}
	k.refusal = &agentproto.KeyRefusal{Statement: kind, ID: p.ID, Reason: reason}
}

// Pin takes the server's key from an enrollment or heartbeat answer. The
// first key is pinned on first use (ADR-0017), and nothing else is ever added
// this way: a key the agent already trusts has its generation learnt when it
// was unknown; any other key is left to the statements. It returns true when
// the key is trusted afterwards.
func (k *KeyStore) Pin(key string, generation int64) (trusted bool, err error) {
	if key == "" {
		return false, nil
	}
	pub, err := agentproto.DecodeKey(key)
	if err != nil {
		return false, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	list := held(k.Config)
	if len(list) == 0 {
		next := []state.JobKey{{Key: key, Generation: max(generation, 0)}}
		return true, k.commit(next, k.Config.DroppedJobKeys, k.Config.KeyTransitionUntil)
	}
	for i, j := range list {
		have, derr := agentproto.DecodeKey(j.Key)
		if derr != nil || !have.Equal(pub) {
			continue
		}
		if j.Generation == 0 && generation > 0 {
			next := slices.Clone(list)
			next[i].Generation = generation
			return true, k.commit(next, k.Config.DroppedJobKeys, k.Config.KeyTransitionUntil)
		}
		return true, nil
	}
	return false, nil
}

// commit writes the configuration with the new keys, oldest first, and only
// then makes them the ones the store holds: agent.json is written before the
// agent acts on a change.
func (k *KeyStore) commit(keys, dropped []state.JobKey, until time.Time) error {
	sorted := slices.Clone(keys)
	slices.SortStableFunc(sorted, func(a, b state.JobKey) int {
		switch {
		case a.Generation < b.Generation:
			return -1
		case a.Generation > b.Generation:
			return 1
		}
		return 0
	})
	next := *k.Config
	next.JobKeys, next.DroppedJobKeys, next.KeyTransitionUntil = sorted, dropped, until
	next.JobKey = ""
	if len(sorted) > 0 {
		next.JobKey = sorted[0].Key
	}
	if err := k.Store.SaveConfig(&next); err != nil {
		return err
	}
	*k.Config = next
	return nil
}

// Answered handles the statements of a heartbeat answer: the hand-over, then
// the cut-over, each applied and written before the next. level is the
// server's protocol level; an answer below 2 cannot carry them. When neither
// is carried, the refusal of an earlier one, which the server has taken, is
// dropped.
func (k *KeyStore) Answered(level int, handover, cutover *agentproto.SignedKeyStatement) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if handover == nil && cutover == nil {
		k.refusal = nil
		return
	}
	if level < 2 {
		k.logger().Warn("refused job key statements from a server that does not speak protocol level 2")
		return
	}
	k.refusal = nil
	if handover != nil {
		k.handleHandover(*handover)
	}
	if cutover != nil {
		k.handleCutover(*cutover)
	}
}

// maxGeneration is the highest generation among the keys, 0 when none is
// known.
func maxGeneration(list []state.JobKey) int64 {
	var g int64
	for _, j := range list {
		g = max(g, j.Generation)
	}
	return g
}

func (k *KeyStore) handled(log state.KeyLog, id string) bool {
	return slices.Contains(log.Handled, id)
}

func (k *KeyStore) remember(log state.KeyLog, p agentproto.KeyStatement) {
	if p.IssuedAt.After(log.Issued) {
		log.Issued = p.IssuedAt
	}
	log.Handled = append(log.Handled, p.ID)
	if len(log.Handled) > keepHandledKeys {
		log.Handled = log.Handled[len(log.Handled)-keepHandledKeys:]
	}
	if err := k.Store.SaveKeyLog(log); err != nil {
		k.logger().Error("saving the key statement log failed", "error", err)
	}
}

func (k *KeyStore) handleHandover(s agentproto.SignedKeyStatement) {
	keys := decode(held(k.Config))
	p, err := agentproto.VerifyHandover(keys, s, k.DeviceID, k.Install, k.now())
	if err != nil {
		k.refuse(stmtHandover, p, err.Error())
		return
	}
	log := k.Store.LoadKeyLog()
	if k.handled(log, p.ID) {
		return // offered again, or by another server: nothing twice
	}
	list := held(k.Config)
	pub, _ := agentproto.DecodeKey(p.Key)
	// A key already trusted at the same generation: nothing changes, and it
	// is no error (two servers, a repeated answer).
	for i, j := range list {
		have, derr := agentproto.DecodeKey(j.Key)
		if derr != nil || !have.Equal(pub) {
			continue
		}
		switch {
		case j.Generation == p.Generation:
			return
		case j.Generation == 0:
			next := slices.Clone(list)
			next[i].Generation = p.Generation
			if err := k.commit(next, k.Config.DroppedJobKeys, k.Config.KeyTransitionUntil); err != nil {
				k.refuse(stmtHandover, p, "saving the keys failed: "+err.Error())
			}
			return
		default:
			k.refuse(stmtHandover, p, fmt.Sprintf("the key is trusted at generation %d, not %d", j.Generation, p.Generation))
			return
		}
	}
	switch {
	case p.IssuedAt.Before(log.Issued):
		k.refuse(stmtHandover, p, "issued before a statement already handled")
		return
	case p.Generation <= maxGeneration(list):
		k.refuse(stmtHandover, p, fmt.Sprintf("generation %d is not above the %d this agent trusts", p.Generation, maxGeneration(list)))
		return
	case p.Generation > k.now().Add(agentproto.MaxSkew).UnixMilli():
		// Not remembered: offered again with each heartbeat, and accepted
		// once the clock reaches it.
		k.refuse(stmtHandover, p, "the key's generation is more than 5 minutes ahead of this computer's clock")
		return
	case len(list) >= agentproto.MaxTrustedKeys:
		k.refuse(stmtHandover, p, "it would leave this agent trusting more than 4 keys")
		return
	}
	next := append(slices.Clone(list), state.JobKey{Key: p.Key, Generation: p.Generation})
	// A key the agent dropped before and is handed again would be trusted
	// again; the generation check above already refuses one older than the
	// newest, and a dropped key leaves the list of dropped.
	dropped := slices.DeleteFunc(slices.Clone(k.Config.DroppedJobKeys), func(j state.JobKey) bool { return j.Key == p.Key })
	if err := k.commit(next, dropped, k.Config.KeyTransitionUntil); err != nil {
		k.refuse(stmtHandover, p, "saving the keys failed: "+err.Error())
		return
	}
	k.remember(log, p)
	k.recordStatement(agentproto.InstructionHandover, pub, keys.SignerOf(func(key ed25519.PublicKey) bool {
		_, err := agentproto.VerifyHandover(key, s, k.DeviceID, k.Install, k.now())
		return err == nil
	}))
	k.logger().Info("trusts a new server job key", "fingerprint", agentproto.Fingerprint(pub), "generation", p.Generation)
}

func (k *KeyStore) handleCutover(s agentproto.SignedKeyStatement) {
	keys := decode(held(k.Config))
	p, err := agentproto.VerifyCutover(keys, s, k.DeviceID, k.Install, k.now())
	if err != nil {
		k.refuse(stmtCutover, p, err.Error())
		return
	}
	log := k.Store.LoadKeyLog()
	if k.handled(log, p.ID) {
		return
	}
	list := held(k.Config)
	pub, _ := agentproto.DecodeKey(p.Key)
	idx := slices.IndexFunc(list, func(j state.JobKey) bool {
		have, err := agentproto.DecodeKey(j.Key)
		return err == nil && have.Equal(pub)
	})
	if idx < 0 {
		k.refuse(stmtCutover, p, "the key is not one this agent trusts")
		return
	}
	// The newest key it trusts: the last of the list, which is sorted by
	// generation (a generation unknown sorts first).
	if idx != len(list)-1 {
		k.refuse(stmtCutover, p, "the key is not the newest this agent trusts")
		return
	}
	if list[idx].Generation != 0 && list[idx].Generation != p.Generation {
		k.refuse(stmtCutover, p, fmt.Sprintf("the key is trusted at generation %d, not %d", list[idx].Generation, p.Generation))
		return
	}
	if len(list) == 1 {
		// A cut-over to the only key it trusts changes nothing.
		if list[0].Generation == 0 {
			next := []state.JobKey{{Key: list[0].Key, Generation: p.Generation}}
			if err := k.commit(next, k.Config.DroppedJobKeys, k.Config.KeyTransitionUntil); err != nil {
				k.refuse(stmtCutover, p, "saving the keys failed: "+err.Error())
			}
		}
		return
	}
	if p.IssuedAt.Before(log.Issued) {
		k.refuse(stmtCutover, p, "issued before a statement already handled")
		return
	}
	dropped := slices.Clone(k.Config.DroppedJobKeys)
	for i, j := range list {
		if i != idx && !slices.ContainsFunc(dropped, func(d state.JobKey) bool { return d.Key == j.Key }) {
			dropped = append(dropped, j)
		}
	}
	if len(dropped) > agentproto.MaxDroppedKeys {
		dropped = dropped[len(dropped)-agentproto.MaxDroppedKeys:]
	}
	kept := []state.JobKey{{Key: p.Key, Generation: max(list[idx].Generation, p.Generation)}}
	if err := k.commit(kept, dropped, k.now().Add(TransitionLength)); err != nil {
		k.refuse(stmtCutover, p, "saving the keys failed: "+err.Error())
		return
	}
	k.remember(log, p)
	// A cut-over is signed by the key it names.
	k.recordStatement(agentproto.InstructionCutover, pub, agentproto.Fingerprint(pub))
	k.logger().Info("trusts only one server job key now", "fingerprint", agentproto.Fingerprint(pub), "generation", p.Generation)
}

// recordStatement logs an accepted statement: its ID in the log is the key's
// fingerprint, and the signer the fingerprint of the key that signed it.
func (k *KeyStore) recordStatement(kind string, introduced ed25519.PublicKey, signer string) {
	if k.Record != nil {
		k.Record(kind, agentproto.Fingerprint(introduced), signer)
	}
}

// ErrLowerGeneration is returned by Replace for a key older than one the
// agent trusts.
var ErrLowerGeneration = errors.New("the agent trusts a key with a higher generation; use --force to replace it anyway")

// Replace is `trust-key`: the keys the agent trusts become the one given. It
// refuses when the agent trusts a key with a higher generation than the one
// given, unless force, so a command deployed by policy that runs again never
// moves a device back to an older key. The keys it replaces are kept as
// dropped. It changes the configuration only; the service is restarted by
// the caller.
func (k *KeyStore) Replace(generation int64, key string, force bool) error {
	pub, err := agentproto.DecodeKey(key)
	if err != nil {
		return err
	}
	if generation < 1 {
		return errors.New("the generation must be a positive number")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	list := held(k.Config)
	if !force && maxGeneration(list) > generation {
		return ErrLowerGeneration
	}
	dropped := slices.Clone(k.Config.DroppedJobKeys)
	for _, j := range list {
		if j.Key == key || slices.ContainsFunc(dropped, func(d state.JobKey) bool { return d.Key == j.Key }) {
			continue
		}
		dropped = append(dropped, j)
	}
	dropped = slices.DeleteFunc(dropped, func(j state.JobKey) bool { return j.Key == key })
	if len(dropped) > agentproto.MaxDroppedKeys {
		dropped = dropped[len(dropped)-agentproto.MaxDroppedKeys:]
	}
	if err := k.commit([]state.JobKey{{Key: key, Generation: generation}}, dropped, time.Time{}); err != nil {
		return err
	}
	k.logger().Info("the job key was replaced by trust-key", "fingerprint", agentproto.Fingerprint(pub), "generation", generation)
	return nil
}

// KeyInfo is a key as `status` shows it.
type KeyInfo struct {
	Fingerprint string
	Generation  int64
}

// View lists the keys a configuration trusts, oldest first, and the ones it
// dropped.
func View(c *state.Config) (trusted, dropped []KeyInfo) {
	conv := func(list []state.JobKey) []KeyInfo {
		var out []KeyInfo
		for _, j := range list {
			if pub, err := agentproto.DecodeKey(j.Key); err == nil {
				out = append(out, KeyInfo{Fingerprint: agentproto.Fingerprint(pub), Generation: j.Generation})
			}
		}
		return out
	}
	return conv(held(c)), conv(c.DroppedJobKeys)
}
