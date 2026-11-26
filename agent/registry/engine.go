// Package registry is the registry editor's builtin (ADR-0067): Go code in
// the agent's own program, run as a child process of it, which reads a
// Windows computer's registry from a typed input and writes its result as
// JSON lines to a file. The engine here is the part that does not touch
// Windows: it opens a path one name at a time through a Backend, checks the
// kernel's name of every key against the refusals, and never lets Windows
// follow a link. The Windows backend is in backend_windows.go.
package registry

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/internal/registryrules"
)

// Errors a Backend answers.
var (
	// ErrDenied is Windows denying access to a key or value.
	ErrDenied = errors.New("access denied")
	// ErrNotFound is a key or value that is not there.
	ErrNotFound = errors.New("not found")
)

// Info is what a key says about itself.
type Info struct {
	Subkeys, Values int
	LastWrite       time.Time
}

// Key is an open key. It is opened with REG_OPTION_OPEN_LINK, so a link is
// the link and never what it points to.
type Key interface {
	// Kernel is the kernel's name of the key, such as
	// \REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Vendor.
	Kernel() string
	Info() (Info, error)
	SubkeyNames() ([]string, error)
	ValueNames() ([]string, error)
	// ValueInfo is a value's raw type and the size of its data.
	ValueInfo(name string) (typ uint32, size int, err error)
	// ReadValue reads a value's raw bytes, whole.
	ReadValue(name string) (typ uint32, data []byte, err error)
	// OpenChild opens a subkey without following a link.
	OpenChild(name string) (Key, error)
	// LinkTarget says whether the key is a link, and its target text.
	LinkTarget() (target string, isLink bool)
	Close()
}

// HiveFile is one entry of the hivelist: the kernel's name of a loaded
// hive's root and the file it was loaded from.
type HiveFile struct {
	Key  string
	File string
}

// Backend is the registry as the engine reads it.
type Backend interface {
	// Root opens a hive's root in a view.
	Root(h registryrules.Hive, v registryrules.View) (Key, error)
	// Hivelist reads HKLM\SYSTEM\CurrentControlSet\Control\hivelist.
	Hivelist() ([]HiveFile, error)
	// SIDLabel names the user of a SID, or "".
	SIDLabel(sid string) string
	// Arch is the machine's architecture, as agentproto names it.
	Arch() string
}

// Options are what a run is given besides its input.
type Options struct {
	AgentVersion string
	// Now and ListBudget/SearchBudget are replaced by tests.
	Now          func() time.Time
	ListBudget   time.Duration
	SearchBudget time.Duration
}

// Run reads the registry as the input asks and writes its result lines to
// out. Whatever the outcome, the lines written so far are whole; the last
// is "end" unless the process is stopped.
func Run(in agentproto.RegistryInput, be Backend, out io.Writer, o Options) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.ListBudget == 0 {
		o.ListBudget = agentproto.RegListSeconds * time.Second
	}
	if o.SearchBudget == 0 {
		o.SearchBudget = agentproto.RegSearchSeconds * time.Second
	}
	e := &engine{in: in, be: be, o: o, w: &lineWriter{w: bufio.NewWriter(out), max: agentproto.MaxResultFile - 8<<10}}
	e.view = registryrules.View(in.View)
	e.start = o.Now()
	budget := o.ListBudget
	if in.Op == agentproto.RegOpSearch || in.Op == agentproto.RegOpExport {
		budget = o.SearchBudget
	}
	e.deadline = e.start.Add(budget)
	err := e.run()
	if ferr := e.w.flush(); err == nil {
		err = ferr
	}
	return err
}

type lineWriter struct {
	w   *bufio.Writer
	n   int
	max int
}

var errFull = errors.New("the result is full")

// put writes one line unless it would pass the file's bound.
func (l *lineWriter) put(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if !agentproto.ValidRegistryText(b) {
		return fmt.Errorf("registry: a line holds text that cannot be sent: %.60s", b)
	}
	if l.n+len(b)+1 > l.max {
		return errFull
	}
	l.n += len(b) + 1
	if _, err := l.w.Write(b); err != nil {
		return err
	}
	return l.w.WriteByte('\n')
}

// final writes a line even where the bound is reached: the end line, which
// has room reserved.
func (l *lineWriter) final(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	l.n += len(b) + 1
	if _, err := l.w.Write(b); err != nil {
		return err
	}
	return l.w.WriteByte('\n')
}

func (l *lineWriter) flush() error { return l.w.Flush() }

type engine struct {
	in       agentproto.RegistryInput
	be       Backend
	o        Options
	w        *lineWriter
	view     registryrules.View
	start    time.Time
	deadline time.Time
	// extra are the loaded copies of SAM and SECURITY found in the hivelist.
	extra []registryrules.Prefix
	// hive and names are the key asked for, resolved to a physical hive.
	hive  registryrules.Hive
	names []string
	// checked caches which mounted hives were looked into.
	checked map[string]bool

	end agentproto.RegEnd
}

func (e *engine) expired() bool { return !e.o.Now().Before(e.deadline) }

// failure is a read that stopped at one key: the code the result says and
// the text.
type failure struct {
	code, msg string
	refusal   *registryrules.Refusal
	kernel    string
}

func (f *failure) Error() string { return f.msg }

func (e *engine) run() error {
	in := e.in
	begin := agentproto.RegBegin{T: agentproto.LineBegin, V: agentproto.RegistryResultVersion, Op: in.Op, Hive: in.Hive, View: in.View,
		Path: nonNil(in.Path), Rules: registryrules.Version, AgentVersion: e.o.AgentVersion, Arch: e.be.Arch(), Cursor: in.Cursor}
	if err := e.w.put(begin); err != nil {
		return err
	}
	if err := in.Check(); err != nil {
		return e.fail(&failure{code: agentproto.ErrCodeFailed, msg: err.Error()})
	}
	e.hive, e.names = registryrules.Resolve(registryrules.Hive(in.Hive), append([]string{}, in.Path...))
	if hl, err := e.be.Hivelist(); err == nil {
		e.extra = copiesFromHivelist(hl)
	}
	if r := registryrules.CheckWith(registryrules.Hive(in.Hive), e.view, in.Path, e.extra); r != nil {
		return e.fail(&failure{code: agentproto.ErrCodeRefused, msg: "Refused by EasyRMM: " + r.Rule + ".", refusal: r})
	}
	k, err := e.openPath(e.hive, e.names, 0)
	if err != nil {
		return e.fail(err)
	}
	defer k.Close()
	switch in.Op {
	case agentproto.RegOpList:
		err = e.list(k)
	case agentproto.RegOpValue:
		err = e.value(k)
	case agentproto.RegOpSearch:
		err = e.search(k)
	case agentproto.RegOpExport:
		err = e.export(k)
	}
	if err != nil {
		var f *failure
		if errors.As(err, &f) {
			return e.fail(f)
		}
		if !errors.Is(err, errFull) {
			return err
		}
		if e.end.StoppedBy == "" {
			e.end.StoppedBy = agentproto.StoppedSize
		}
	}
	return e.finish(true)
}

func nonNil(p []string) []string {
	if p == nil {
		return []string{}
	}
	return p
}

// finish writes the end line.
func (e *engine) finish(complete bool) error {
	e.end.T = agentproto.LineEnd
	e.end.Complete = complete && e.end.StoppedBy == ""
	e.end.ElapsedMS = e.o.Now().Sub(e.start).Milliseconds()
	return e.w.final(e.end)
}

// fail writes what could not be read, and ends: the work finished with an
// answer, which is that there is nothing to show.
func (e *engine) fail(err error) error {
	var f *failure
	if !errors.As(err, &f) {
		f = &failure{code: agentproto.ErrCodeFailed, msg: err.Error()}
	}
	if f.refusal != nil {
		path := nonNil(e.in.Path)
		if err := e.w.final(agentproto.RegRefused{T: agentproto.LineRefused, Path: path, Rule: f.refusal.Rule, Kernel: f.kernel}); err != nil {
			return err
		}
	}
	if err := e.w.final(agentproto.RegError{T: agentproto.LineError, Code: f.code, Message: f.msg}); err != nil {
		return err
	}
	return e.finish(true)
}

// ownHives are the names Windows itself loads under HKLM; a hive under any
// other name is looked into before anything is read from it.
var ownHives = []string{"HARDWARE", "SAM", "SECURITY", "SOFTWARE", "SYSTEM", "BCD00000000", "DRIVERS", "COMPONENTS",
	"SCHEMA", "OSDATA", "BBI", "WDBOOT", "ELAM", "AMSI", "SYSTEM_COPY"}

// copiesFromHivelist finds hives loaded from a file named SAM or SECURITY,
// with any extension or none and in any folder, and refuses them wherever
// they are mounted (ADR-0067, Refused).
func copiesFromHivelist(hl []HiveFile) []registryrules.Prefix {
	var out []registryrules.Prefix
	for _, h := range hl {
		file := h.File
		if i := strings.LastIndexAny(file, `\/`); i >= 0 {
			file = file[i+1:]
		}
		if i := strings.IndexByte(file, '.'); i >= 0 {
			file = file[:i]
		}
		if !registryrules.Equal(file, "SAM") && !registryrules.Equal(file, "SECURITY") {
			continue
		}
		hh, names, err := registryrules.ParseText(h.Key)
		if err != nil || len(names) == 0 {
			continue
		}
		out = append(out, registryrules.Prefix{Hive: hh, Names: names})
	}
	return out
}

// kernelRefusal checks the kernel's name of an open key against every
// refusal.
func (e *engine) kernelRefusal(k Key) *failure {
	h, names, err := registryrules.ParseText(k.Kernel())
	if err != nil {
		return nil //nolint:nilerr // a name the rules cannot read is not one they name
	}
	if r := registryrules.CheckWith(h, e.view, names, e.extra); r != nil {
		return &failure{code: agentproto.ErrCodeRefused, msg: "Refused by EasyRMM: " + r.Rule + ".", refusal: r, kernel: k.Kernel()}
	}
	return nil
}

// mountedCopy looks into a hive that is not one of Windows' own: one that
// holds SAM\Domains or Policy\Secrets is a copy of SAM or SECURITY, whatever
// it is called, and is refused.
func (e *engine) mountedCopy(h registryrules.Hive, name string, k Key) *failure {
	own := false
	switch h {
	case registryrules.HKLM:
		own = slices.ContainsFunc(ownHives, func(o string) bool { return registryrules.Equal(o, name) })
	case registryrules.HKU:
		own = name == ".DEFAULT" || strings.HasPrefix(strings.ToUpper(name), "S-1-")
	}
	if own {
		return nil
	}
	if e.checked == nil {
		e.checked = map[string]bool{}
	}
	key := string(h) + `\` + registryrules.Fold(name)
	if bad, done := e.checked[key]; done {
		if bad {
			return &failure{code: agentproto.ErrCodeRefused, msg: "Refused by EasyRMM: a loaded copy of SAM or SECURITY.", refusal: &registryrules.Refusal{Rule: "a loaded copy of SAM or SECURITY"}, kernel: k.Kernel()}
		}
		return nil
	}
	hasPath := func(names ...string) bool {
		cur := k
		for i, n := range names {
			next, err := cur.OpenChild(n)
			if i > 0 {
				cur.Close()
			}
			if err != nil {
				return false
			}
			cur = next
		}
		cur.Close()
		return true
	}
	bad := hasPath("SAM", "Domains") || hasPath("Policy", "Secrets")
	e.checked[key] = bad
	if bad {
		return &failure{code: agentproto.ErrCodeRefused, msg: "Refused by EasyRMM: a loaded copy of SAM or SECURITY.", refusal: &registryrules.Refusal{Rule: "a loaded copy of SAM or SECURITY"}, kernel: k.Kernel()}
	}
	return nil
}

// maxLinks bounds the links one path follows.
const maxLinks = 8

// openPath opens a path one name at a time from the hive's root, checking
// each name before it is opened and the kernel's name after. A link is
// followed by the engine itself, and only for a read, only to a target that
// passes the refusals and stays in the hive it started in.
func (e *engine) openPath(h registryrules.Hive, names []string, links int) (Key, error) {
	k, err := e.be.Root(h, e.view)
	if err != nil {
		return nil, mapErr(err, "the hive")
	}
	for i, name := range names {
		if r := registryrules.CheckWith(h, e.view, names[:i+1], e.extra); r != nil {
			k.Close()
			return nil, &failure{code: agentproto.ErrCodeRefused, msg: "Refused by EasyRMM: " + r.Rule + ".", refusal: r}
		}
		child, err := k.OpenChild(name)
		k.Close()
		if err != nil {
			return nil, mapErr(err, "the key")
		}
		k = child
		if f := e.kernelRefusal(k); f != nil {
			k.Close()
			return nil, f
		}
		if i == 0 {
			if f := e.mountedCopy(h, name, k); f != nil {
				k.Close()
				return nil, f
			}
		}
		if target, ok := k.LinkTarget(); ok {
			k.Close()
			th, tn, perr := registryrules.ParseText(target)
			if perr != nil || links >= maxLinks || !sameHive(h, names, th, tn) {
				return nil, &failure{code: agentproto.ErrCodeFailed, msg: "The key is a link to " + agentproto.SafeText(target) + ", which EasyRMM does not follow."}
			}
			rest := append(append([]string{}, tn...), names[i+1:]...)
			return e.openPath(th, rest, links+1)
		}
	}
	return k, nil
}

// sameHive says a link's target stays in the hive the path started in: the
// machine's hives to the machine's, or one user's HKU\<SID> and
// HKU\<SID>_Classes between themselves.
func sameHive(h registryrules.Hive, names []string, th registryrules.Hive, tn []string) bool {
	if h != th {
		return false
	}
	if h == registryrules.HKU {
		if len(names) == 0 || len(tn) == 0 {
			return false
		}
		return registryrules.Equal(strings.TrimSuffix(strings.ToUpper(names[0]), "_CLASSES"), strings.TrimSuffix(strings.ToUpper(tn[0]), "_CLASSES"))
	}
	return true
}

func mapErr(err error, what string) error {
	switch {
	case errors.Is(err, ErrDenied):
		return &failure{code: agentproto.ErrCodeDenied, msg: "Windows denied access to " + what + "."}
	case errors.Is(err, ErrNotFound):
		return &failure{code: agentproto.ErrCodeNotFound, msg: "The key is not there: it may have been removed since it was listed."}
	}
	return &failure{code: agentproto.ErrCodeFailed, msg: "Reading " + what + " failed: " + err.Error()}
}

// order sorts names in ordinal ignore-case order, the order pages and
// cursors use.
func order(names []string) {
	type keyed struct{ fold, name string }
	k := make([]keyed, len(names))
	for i, n := range names {
		k[i] = keyed{registryrules.Fold(n), n}
	}
	slices.SortFunc(k, func(a, b keyed) int {
		if c := strings.Compare(a.fold, b.fold); c != 0 {
			return c
		}
		return strings.Compare(a.name, b.name)
	})
	for i := range k {
		names[i] = k[i].name
	}
}

// after reports whether name sorts after the cursor's name.
func after(name, cursor string) bool {
	if c := strings.Compare(registryrules.Fold(name), registryrules.Fold(cursor)); c != 0 {
		return c > 0
	}
	return name > cursor
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (e *engine) path(extra ...string) []string {
	return append(append([]string{}, e.in.Path...), extra...)
}

// list writes a key and one page of its subkeys and values.
func (e *engine) list(k Key) error {
	info, err := k.Info()
	if err != nil {
		return mapErr(err, "the key")
	}
	if err := e.w.put(agentproto.RegKey{T: agentproto.LineKey, Kernel: agentproto.SafeText(k.Kernel()), Subkeys: info.Subkeys,
		Values: info.Values, LastWrite: stamp(info.LastWrite), ReadAt: stamp(e.o.Now())}); err != nil {
		return err
	}
	maxSub, maxVal := e.in.MaxSubkeys, e.in.MaxValues
	if maxSub == 0 {
		maxSub = agentproto.RegMaxSubkeys
	}
	if maxVal == 0 {
		maxVal = agentproto.RegMaxValues
	}
	subs, err := k.SubkeyNames()
	if err != nil {
		return mapErr(err, "the key's subkeys")
	}
	order(subs)
	var cur agentproto.RegistryCursor
	if e.in.Cursor != nil {
		cur = *e.in.Cursor
	}
	n, written := 0, 0
	var last string
	for _, name := range subs {
		if cur.Subkey != nil && !after(name, *cur.Subkey) {
			continue
		}
		if written >= maxSub || e.w.n > agentproto.RegPageBytes {
			e.end.MoreSubkeys, e.end.NextSubkey = true, last
			break
		}
		n++
		line := e.subkey(k, name)
		if err := e.w.put(line); err != nil {
			if errors.Is(err, errFull) {
				e.end.MoreSubkeys, e.end.NextSubkey = true, last
				break
			}
			return err
		}
		written++
		last = name
	}
	vals, err := k.ValueNames()
	if err != nil {
		return mapErr(err, "the key's values")
	}
	order(vals)
	written, last = 0, ""
	for _, name := range vals {
		if cur.Value != nil && !after(name, *cur.Value) {
			continue
		}
		if written >= maxVal || e.w.n > agentproto.RegPageBytes {
			e.end.MoreValues, e.end.NextValue = true, last
			break
		}
		if err := e.w.put(e.valueLine(k, name, false)); err != nil {
			if errors.Is(err, errFull) {
				e.end.MoreValues, e.end.NextValue = true, last
				break
			}
			return err
		}
		written++
		last = name
	}
	return nil
}

// subkey describes one subkey of a listed key: refused, a link, denied, or
// its counts. A refused key is never opened.
func (e *engine) subkey(parent Key, name string) agentproto.RegSubkey {
	line := agentproto.RegSubkey{T: agentproto.LineSubkey, Name: agentproto.SafeText(name), RawName: agentproto.RawText(name), Subkeys: -1, Values: -1}
	if r := registryrules.CheckWith(registryrules.Hive(e.in.Hive), e.view, e.path(name), e.extra); r != nil {
		line.State, line.Rule = agentproto.StateRefused, r.Rule
		return line
	}
	if e.hive == registryrules.HKU && len(e.names) == 0 && !strings.HasSuffix(strings.ToUpper(name), "_CLASSES") {
		line.Label = agentproto.SafeText(e.be.SIDLabel(name))
	}
	if e.expired() {
		return line // out of time: the name only, counts unknown
	}
	child, err := parent.OpenChild(name)
	if err != nil {
		if errors.Is(err, ErrDenied) {
			line.State = agentproto.StateDenied
		}
		return line
	}
	defer child.Close()
	if f := e.kernelRefusal(child); f != nil {
		line.State, line.Rule = agentproto.StateRefused, f.refusal.Rule
		return line
	}
	if len(e.names) == 0 {
		if f := e.mountedCopy(e.hive, name, child); f != nil {
			line.State, line.Rule = agentproto.StateRefused, f.refusal.Rule
			return line
		}
	}
	if target, ok := child.LinkTarget(); ok {
		line.State, line.Target = agentproto.StateLink, agentproto.SafeText(target)
		return line
	}
	if info, err := child.Info(); err == nil {
		line.Subkeys, line.Values = info.Subkeys, info.Values
		line.LastWrite = stamp(info.LastWrite)
	}
	return line
}

// pageLimit is how much of a value a list shows.
const pageLimit = agentproto.RegValuePageBytes

// valueLine reads one value for a list (alone: false) or a value read
// (alone: true). A masked value is returned with its type and size only.
func (e *engine) valueLine(k Key, name string, alone bool) agentproto.RegValue {
	typ, size, err := k.ValueInfo(name)
	if err != nil {
		v := agentproto.EncodeRegValue(name, 0, nil, false, false, 0)
		v.Denied = errors.Is(err, ErrDenied)
		v.NoData = true
		return v
	}
	if registryrules.IsMasked(name, typ) {
		v := agentproto.EncodeRegValue(name, typ, nil, true, false, 0)
		v.Size = size
		return v
	}
	if !alone && size > pageLimit {
		v := agentproto.EncodeRegValue(name, typ, nil, false, false, 0)
		v.Size, v.NoData = size, true
		return v
	}
	if size > 16<<20 {
		v := agentproto.EncodeRegValue(name, typ, nil, false, false, 0)
		v.Size, v.NoData = size, true
		return v
	}
	_, data, err := k.ReadValue(name)
	if err != nil {
		v := agentproto.EncodeRegValue(name, typ, nil, false, false, 0)
		v.Size, v.NoData, v.Denied = size, true, errors.Is(err, ErrDenied)
		return v
	}
	limit := pageLimit
	if alone {
		limit = agentproto.RegValueReadBytes
	}
	return agentproto.EncodeRegValue(name, typ, data, false, alone, limit)
}

// value writes the one value a value read asks for.
func (e *engine) value(k Key) error {
	name := *e.in.ValueName
	if _, _, err := k.ValueInfo(name); err != nil {
		if errors.Is(err, ErrNotFound) {
			return &failure{code: agentproto.ErrCodeNotFound, msg: "The value is not there: it may have been removed since it was listed."}
		}
		return mapErr(err, "the value")
	}
	return e.w.put(e.valueLine(k, name, true))
}
