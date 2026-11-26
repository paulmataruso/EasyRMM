// Package winmod is the framework of ADR-0073's Windows management modules:
// the catalog of fixed, versioned actions (each with an embedded script
// pinned by its SHA-256), the validation of typed parameters, and the typed
// result an action's script prints. A module supplies only its actions; the
// jobs package runs them as the winmod job kind.
package winmod

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
	"github.com/paulmataruso/easyrmm/server/internal/modules"
	"github.com/paulmataruso/easyrmm/server/internal/rbac"
)

// ResultPrefix starts the last line of an action's output.
const ResultPrefix = "EASYRMM-WINMOD-RESULT-V1 "

// MaxResultBytes is the largest structured result (ADR-0073: F2's limit).
const MaxResultBytes = 64 << 10

// Type is the kind of value a parameter takes.
type Type string

// Parameter types.
const (
	// Name is the name of a user, group, share or similar: letters, digits,
	// spaces and . _ - @ $ ' only.
	Name Type = "name"
	// Path is an absolute drive path without `..` or device prefixes.
	Path Type = "path"
	// GUID is parsed and written in its canonical lower-case form.
	GUID Type = "guid"
	// SID is a Windows security identifier.
	SID Type = "sid"
	// Int is a whole number within Min and Max.
	Int Type = "int"
	// Bool is true or false.
	Bool Type = "bool"
	// Enum is one of Values.
	Enum Type = "enum"
	// Text is free text of Min to Max characters without control
	// characters; a Secret parameter is of this type.
	Text Type = "text"
	// DN is an LDAP distinguished name of CN, OU and DC parts whose values
	// hold letters, digits, spaces and . _ - only (ADR-0075).
	DN Type = "dn"
)

// Param declares one parameter of an action.
type Param struct {
	Name     string
	Type     Type
	Required bool
	// Min and Max bound the length (Name, Path, Text) or the value (Int).
	// Max 0 means the type's default.
	Min, Max int
	Values   []string
	// Secret values are sealed apart, placed in the job at delivery only,
	// and never audited or logged.
	Secret bool
	// Pattern, for a Text parameter, is a regular expression the whole
	// value must match; Check returns why a value that does not suit
	// is refused, or "". Both run after the common text checks.
	Pattern *regexp.Regexp
	Check   func(string) string
	// Sensitive values are audited as their length and SHA-256 only.
	Sensitive bool
	// AllowEmpty lets a Text be empty (a way to say "clear this").
	AllowEmpty bool
	// Needs, when set, is a permission the caller must hold on the device
	// to send this parameter at all (a stronger permission than the
	// action's own, for a stronger use of it).
	Needs rbac.Permission
	// Generate, on an optional Secret, has the server make the value when
	// the request leaves it out (a password), and show it to the caller
	// once in the answer (ADR-0075).
	Generate bool
	// RefuseWellKnown, on a SID, accepts only an ordinary domain account or
	// group (a domain SID with a relative ID of 1000 or more): the built-in
	// and well-known principals, which hold the domain, are refused
	// whatever their name (ADR-0075 section 4, the server's check).
	RefuseWellKnown bool
}

// Action is one fixed action of a module.
type Action struct {
	Module modules.Module
	// Name is "<module>.<action>", the name in the API and the audit.
	Name    string
	Label   string
	Version int
	// Script is the embedded PowerShell, ScriptSHA256 its hex SHA-256
	// written in the catalog and checked when it is built and by a test.
	// A native action has neither.
	Script       string
	ScriptSHA256 string
	// Native, when set, makes the action's executor native (ADR-0073,
	// amended by ADR-0081): agent Go code of this name does the work, and no
	// script exists. It is for an action that handles a secret a script's
	// output, a transcript or a pipe could leak (BitLocker's recovery
	// password). The catalog entry, permission, audit and lint are the
	// same as a script action's; only what runs differs.
	Native string
	// Shell is the script's shell; empty is Windows PowerShell.
	Shell  string
	Params []Param
	// Permission opens the action; Sensitive says its result is served
	// only with the module's view_sensitive permission.
	Permission rbac.Permission
	Sensitive  bool
	// SensitivePermission opens a Sensitive action's result (the module's
	// view_sensitive).
	SensitivePermission rbac.Permission
	// Destructive actions are confirmed with "<Name>:<subject>" and need a
	// step-up; so does a Credential action (a password reset).
	Destructive bool
	Credential  bool
	// Check, when set, is the module's own check of the parameters after
	// the generic ones passed: the values in their canonical forms, by name.
	// It returns an *apperr.Error (an invalid field, or a conflict).
	Check func(params map[string]any) error
	// Subject names the parameter that is the confirmation's subject.
	Subject string
	// Confirm makes the action need the typed confirmation without a
	// step-up (ADR-0077's tier 2: a change that is not a loss). A
	// destructive action always needs it. The subject may be empty: the
	// confirmation is then the action's name and a colon.
	Confirm bool
	// SubjectIsDeviceName says the subject parameter is the computer's name:
	// the server compares it, trimmed and ignoring case, with the target
	// device's real name when the job is created.
	SubjectIsDeviceName bool
	// Timeout is the script's time limit in seconds.
	Timeout int
	// Keep is how long the job, its params and its result are kept: an hour
	// for a read, seven days for a change, minutes for a sensitive result.
	Keep time.Duration
	// Decode checks the result's data against the action's schema and
	// returns it in its stored form; Typed makes one from a Go type.
	Decode func(json.RawMessage) (json.RawMessage, error)
	// CountField names an array in the data whose length the audit records.
	CountField string
	// Freshness, when above zero, makes the action a snapshot read: a
	// successful result is stored in windows_module_snapshots and is fresh
	// for this long (ADR-0073 section 5: 5 minutes by default).
	Freshness time.Duration
	// Schedule, when above zero, has the server read the action on every
	// computer that has the module's role, at most this often (hourly at
	// least), while the module is on and the organization is allowed. Only
	// for a read with no required parameters that an alert needs.
	Schedule time.Duration
	// Changes says a successful run changes the module's state, so the
	// module's snapshots of the device are dropped.
	Changes bool
	// NeedsEscrow says the action turns on disk encryption: the server makes
	// the job only when the keystore can verify an escrowed recovery key now
	// and the organization has an escrow key (ADR-0081 section 5), and the
	// agent starts encryption only after that key is verified.
	NeedsEscrow bool
}

// IsPlainRead says the action only reads: it changes nothing, asks for no
// confirmation or step-up, runs as a script and needs a "view" permission. Only
// such an action is read on a tab's own (ADR-0073 section 5, as amended).
func (a Action) IsPlainRead() bool {
	return !a.Changes && !a.NeedsConfirm() && !a.NeedsStepUp() && !a.IsNative() && strings.HasSuffix(string(a.Permission), ".view")
}

// IsNative says the action's executor is agent Go code, not a script.
func (a Action) IsNative() bool { return a.Native != "" }

// Shell returns the action's shell.
func (a Action) shell() string {
	if a.Shell == "" {
		return agentproto.ShellPowerShell
	}
	return a.Shell
}

// ShellName is the shell the action's script runs in.
func (a Action) ShellName() string { return a.shell() }

// NeedsConfirm says whether the action needs the typed confirmation.
func (a Action) NeedsConfirm() bool { return a.Destructive || a.Confirm }

// NeedsStepUp says whether the action needs a step-up and a confirmation.
func (a Action) NeedsStepUp() bool { return a.Destructive || a.Credential }

// ConfirmText is what a request's confirmation must say for the subject.
func (a Action) ConfirmText(subject string) string { return a.Name + ":" + subject }

// Catalog is the set of actions the server can run.
type Catalog struct {
	byName map[string]Action
}

// ErrScriptPin is a catalog entry whose script does not match its pinned hash.
var ErrScriptPin = errors.New("winmod: a script does not match its pinned SHA-256")

// NewCatalog checks each action and returns the catalog: names are
// "<module>.<action>" and unique, the script hashes match their pins, and a
// destructive action names its confirmation subject.
func NewCatalog(actions ...Action) (*Catalog, error) {
	c := &Catalog{byName: map[string]Action{}}
	for _, a := range actions {
		if _, ok := readThrough[a.Name]; ok && a.Freshness <= 0 && a.IsPlainRead() {
			a.Freshness = ReadFreshness
		}
		if err := a.check(); err != nil {
			return nil, fmt.Errorf("winmod: action %q: %w", a.Name, err)
		}
		if _, dup := c.byName[a.Name]; dup {
			return nil, fmt.Errorf("winmod: action %q is in the catalog twice", a.Name)
		}
		c.byName[a.Name] = a
	}
	return c, nil
}

var nativeName = regexp.MustCompile(`^[a-z][a-z0-9_.]{2,63}$`)

var actionName = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

func (a Action) check() error {
	switch {
	case !actionName.MatchString(a.Name) || !strings.HasPrefix(a.Name, string(a.Module)+"."):
		return errors.New("the name must be <module>.<action>")
	case a.IsNative() && (a.Script != "" || a.ScriptSHA256 != "" || a.Shell != "" || !nativeName.MatchString(a.Native)):
		return errors.New("a native action names its handler and has no script, pin or shell")
	case a.Version < 1 || (a.Script == "" && !a.IsNative()) || a.Decode == nil || a.Permission == "" || a.Timeout < 1 || a.Keep <= 0:
		return errors.New("version, script, decoder, permission, timeout and retention are required")
	case !a.IsNative() && a.ScriptSHA256 != agentproto.HashScript(a.Script):
		return ErrScriptPin
	case a.Sensitive && a.SensitivePermission == "":
		return errors.New("a sensitive action names the permission that opens its result")
	case (a.Destructive || a.Confirm) && a.Subject == "":
		return errors.New("a confirmed action names its confirmation subject")
	case a.Schedule > 0 && (a.Freshness <= 0 || a.Schedule < time.Hour || a.Destructive || a.Credential || a.Changes):
		return errors.New("a scheduled action is a snapshot read, run at most hourly")
	case a.Freshness > 0 && (a.Destructive || a.Credential || a.Changes):
		return errors.New("a snapshot read does not change anything")
	}
	if !modules.Known(a.Module) {
		return errors.New("unknown module")
	}
	if a.NeedsEscrow && !a.IsNative() {
		return errors.New("an action that needs escrow is native")
	}
	seen := map[string]bool{}
	for _, p := range a.Params {
		if p.Name == "" || seen[p.Name] || (p.Secret && p.Type != Text) {
			return fmt.Errorf("parameter %q is not valid", p.Name)
		}
		seen[p.Name] = true
		if p.Type == Enum && len(p.Values) == 0 {
			return fmt.Errorf("parameter %q has no values", p.Name)
		}
		if p.Pattern != nil && p.Type != Name && p.Type != Text {
			return fmt.Errorf("parameter %q has a bad pattern", p.Name)
		}
		if (p.Generate && (!p.Secret || p.Required)) || (p.RefuseWellKnown && p.Type != SID) {
			return fmt.Errorf("parameter %q is not valid", p.Name)
		}
	}
	if a.Subject != "" && !seen[a.Subject] {
		return errors.New("the confirmation subject is not a parameter")
	}
	return nil
}

// ParamsKey is the key a snapshot is stored under for an action's
// parameters: empty for none, otherwise the SHA-256 of the canonical form.
func ParamsKey(params []byte) (string, error) {
	if len(bytes.TrimSpace(params)) == 0 || string(bytes.TrimSpace(params)) == "null" {
		return "", nil
	}
	canon, err := agentproto.CanonicalParams(params)
	if err != nil {
		return "", err
	}
	if string(canon) == "{}" {
		return "", nil
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}

// Lookup finds an action by its name.
func (c *Catalog) Lookup(name string) (Action, bool) {
	a, ok := c.byName[name]
	return a, ok
}

// Actions lists every action, by name.
func (c *Catalog) Actions() []Action {
	out := make([]Action, 0, len(c.byName))
	for _, a := range c.byName {
		out = append(out, a)
	}
	slices.SortFunc(out, func(x, y Action) int { return strings.Compare(x.Name, y.Name) })
	return out
}

// Typed returns a decoder that reads data strictly as T (no unknown
// fields) and stores it as T marshals.
func Typed[T any]() func(json.RawMessage) (json.RawMessage, error) {
	return func(data json.RawMessage) (json.RawMessage, error) {
		var v T
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&v); err != nil || dec.More() {
			return nil, errors.New("the data does not match the action's result schema")
		}
		return json.Marshal(v)
	}
}

// Result is a decoded result line.
type Result struct {
	OK      bool
	Version int
	// Data is the typed value, in its stored form; nil when the action failed.
	Data  json.RawMessage
	Error *ResultError
	// Count is the length of the action's CountField array.
	Count int
}

// ResultError is how an action reports that it did not do what was asked.
type ResultError struct {
	// Code is a short snake-case reason such as module_missing or
	// protected_target.
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ErrResultShape is an output that is not one valid result line of the
// action's version and schema.
var ErrResultShape = errors.New("winmod: the output is not a valid result")

var errorCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// ParseResult reads the last non-empty line of an action's output: the
// prefix and {ok, version, data, error}. The version must be the one the
// server sent, and data must match the action's schema.
func (a Action) ParseResult(stdout string) (*Result, error) {
	lines := strings.Split(strings.TrimRight(stdout, "\r\n \t"), "\n")
	last := strings.TrimSpace(lines[len(lines)-1])
	body, ok := strings.CutPrefix(last, ResultPrefix)
	if !ok {
		return nil, ErrResultShape
	}
	var env struct {
		OK      bool            `json:"ok"`
		Version int             `json:"version"`
		Data    json.RawMessage `json:"data"`
		Error   *ResultError    `json:"error"`
	}
	dec := json.NewDecoder(strings.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil || dec.More() || env.Version != a.Version {
		return nil, ErrResultShape
	}
	res := &Result{OK: env.OK, Version: env.Version}
	if !env.OK {
		if env.Error == nil || !errorCode.MatchString(env.Error.Code) {
			return nil, ErrResultShape
		}
		msg := []rune(env.Error.Message)
		if len(msg) > 500 {
			msg = msg[:500]
		}
		res.Error = &ResultError{Code: env.Error.Code, Message: string(msg)}
		return res, nil
	}
	if len(env.Data) == 0 || len(env.Data) > MaxResultBytes {
		return nil, ErrResultShape
	}
	data, err := a.Decode(env.Data)
	if err != nil || len(data) > MaxResultBytes {
		return nil, ErrResultShape
	}
	res.Data = data
	if a.CountField != "" {
		var m map[string]json.RawMessage
		var arr []json.RawMessage
		if json.Unmarshal(data, &m) == nil && json.Unmarshal(m[a.CountField], &arr) == nil {
			res.Count = len(arr)
		}
	}
	return res, nil
}
