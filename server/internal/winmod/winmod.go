// Package winmod is the framework of ADR-0073's Windows management modules:
// the catalog of fixed, versioned actions (each with an embedded script
// pinned by its SHA-256), the validation of typed parameters, and the typed
// result an action's script prints. A module supplies only its actions; the
// jobs package runs them as the winmod job kind.
package winmod

import (
	"bytes"
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
	// Sensitive values are audited as their length and SHA-256 only.
	Sensitive bool
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
	Script       string
	ScriptSHA256 string
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
	// Subject names the parameter that is the confirmation's subject.
	Subject string
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
}

// Shell returns the action's shell.
func (a Action) shell() string {
	if a.Shell == "" {
		return agentproto.ShellPowerShell
	}
	return a.Shell
}

// ShellName is the shell the action's script runs in.
func (a Action) ShellName() string { return a.shell() }

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

var actionName = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)

func (a Action) check() error {
	switch {
	case !actionName.MatchString(a.Name) || !strings.HasPrefix(a.Name, string(a.Module)+"."):
		return errors.New("the name must be <module>.<action>")
	case a.Version < 1 || a.Script == "" || a.Decode == nil || a.Permission == "" || a.Timeout < 1 || a.Keep <= 0:
		return errors.New("version, script, decoder, permission, timeout and retention are required")
	case a.ScriptSHA256 != agentproto.HashScript(a.Script):
		return ErrScriptPin
	case a.Sensitive && a.SensitivePermission == "":
		return errors.New("a sensitive action names the permission that opens its result")
	case a.Destructive && a.Subject == "":
		return errors.New("a destructive action names its confirmation subject")
	}
	if _, ok := modules.Lookup(a.Module); !ok {
		return errors.New("unknown module")
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
	}
	if a.Subject != "" && !seen[a.Subject] {
		return errors.New("the confirmation subject is not a parameter")
	}
	return nil
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
