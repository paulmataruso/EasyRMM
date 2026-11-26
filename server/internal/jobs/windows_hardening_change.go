package jobs

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/server/internal/access"
	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/devscope"
)

// Changing Windows computers (ADR-0054, W2, and ADR-0078's fix queue): what
// a Windows apply or undo needs before the server creates the job.

// HardeningConfirm is the mode of the job the server itself queues after an
// apply: it removes the computer's rollback timer, and can only run where
// the agent is reachable. People never create it.
const HardeningConfirm = "confirm"

// GuardMinutes is how long after an apply the computer's own timer waits
// before it undoes the change; GuardConfirmWithin is how long the confirm
// job may wait for its agent, which is always shorter, so that the job
// expires before the timer fires.
const (
	GuardMinutes       = 10
	GuardConfirmWithin = 8 * time.Minute
	// guardSlack is how long past the timer the server waits before it
	// records that the confirmation did not come.
	guardSlack = 2 * time.Minute
)

// Risk tiers (ADR-0078, section 6).
const (
	tierReport    = 0 // there is no setting to change
	tierSafe      = 1 // reversible, no service effect
	tierWorkflow  = 2 // can break a workflow or a user's access
	tierDangerous = 3 // can lock out access or cannot be undone remotely
)

// windowsModuleTiers are the tiers of Windows' modules.
var windowsModuleTiers = map[string]int{
	"autoplay": tierSafe, "wdigest": tierSafe, "name-resolution": tierSafe, "powershell": tierSafe,
	"accounts": tierWorkflow, "anonymous": tierWorkflow, "asr": tierWorkflow, "defender": tierWorkflow,
	"features": tierWorkflow, "lsa-protection": tierWorkflow, "ntlm": tierWorkflow, "printing": tierWorkflow,
	"rdp": tierWorkflow, "smb": tierWorkflow, "smb-signing": tierWorkflow, "tls": tierWorkflow, "uac": tierWorkflow,
	"winrm": tierWorkflow, "firewall": tierDangerous,
	"audit": tierReport, "bitlocker": tierReport, "device-guard": tierReport, "laps": tierReport,
	// ADR-0078, C3: the session's limits and the removable disks' policy can
	// stop a person's work; the rest report.
	"session": tierWorkflow, "removable": tierWorkflow, "mobile-code": tierWorkflow,
	"rights": tierReport, "time": tierReport, "app-control": tierReport, "office": tierReport,
	// ADR-0078, C4: the domain controller checks only read.
	"dc": tierReport,
}

// windowsSettingTiers are the settings that are riskier than their module:
// a firewall profile (the whole module), Remote Desktop's network level
// authentication, account lockout and disabling an account.
var windowsSettingTiers = map[string]int{
	"rdp-nla": tierDangerous, "accounts-guest": tierDangerous, "accounts-lockout-threshold": tierDangerous,
	"accounts-lockout-duration": tierDangerous, "accounts-lockout-reset": tierDangerous,
	// FIPS mode stops programs that use other algorithms, and takes a restart
	// to undo.
	"session-fips": tierDangerous,
}

// windowsSettingTier is a setting's tier.
func windowsSettingTier(s windowsSetting) int {
	// A text only the person can write (a legal notice) is never applied.
	if s.Want == "nonempty" {
		return tierReport
	}
	if t, ok := windowsSettingTiers[s.ID]; ok {
		return t
	}
	return windowsModuleTiers[s.Module]
}

// windowsTier is the highest tier of what the job would change.
func (h Hardening) windowsTier() int {
	tier := tierReport
	for _, s := range windowsSettings {
		if h.Settings != nil && !slices.Contains(h.Settings, s.ID) || h.Settings == nil && !slices.Contains(h.Modules, s.Module) {
			continue
		}
		tier = max(tier, windowsSettingTier(s))
	}
	return tier
}

// HardeningConfirmation is the person's agreement to a Windows change.
type HardeningConfirmation struct {
	// Agreed: the warning was shown and accepted. Every apply and undo.
	Agreed bool `json:"agreed"`
	// Typed is the computer's name as the person typed it. A change that
	// can cut access (tier 3) needs it, on one computer.
	Typed string `json:"typed,omitempty"`
	// StepUp is the proof of a recent step-up (ADR-0055), which tier 3
	// needs as well.
}

// StepUpVerifier checks that the request's session is stepped up (ADR-0055
// §Step-up: a second factor within the last five minutes, on the session).
type StepUpVerifier interface {
	VerifyStepUp(ctx context.Context) error
}

// SetStepUp gives the service the step-up check. Without one, a change of
// tier 3 is refused.
func (s *Service) SetStepUp(v StepUpVerifier) { s.stepUp = v }

// windowsChange is a checked apply or undo.
type windowsChange struct {
	tier   int
	guard  int
	typed  string
	verify func(context.Context) error
}

// windowsChangeGuard checks what a Windows apply or undo needs besides
// permission: the person's agreement, and for tier 3 one computer, its
// name typed and a step-up. It returns what the targets are checked for.
func (s *Service) windowsChangeGuard(c access.Caller, ids []uuid.UUID, h Hardening, in HardeningConfirmation) (*windowsChange, error) {
	f := apperr.Fields{}
	f.Check(in.Agreed, "confirm.agreed", "Confirm that you have read what this change does.")
	ch := &windowsChange{tier: h.windowsTier(), typed: strings.TrimSpace(in.Typed)}
	if h.Mode == HardeningApply {
		ch.guard = GuardMinutes
	}
	if ch.tier == tierDangerous {
		f.Check(len(ids) == 1, "deviceIds", "A change that can cut access to a computer is made on one computer at a time.")
		f.Check(ch.typed != "", "confirm.typed", "Type the computer's name to confirm.")
	}
	if err := f.Err(); err != nil {
		return nil, err
	}
	if ch.tier == tierDangerous {
		if s.stepUp == nil {
			return nil, apperr.Conflict("step_up_required", "This change can cut access to the computer and needs step-up authentication (ADR-0055), which is not available yet, so it cannot be made from here.")
		}
		ch.verify = s.stepUp.VerifyStepUp
	}
	return ch, nil
}

// check looks at the resolved devices: each organization must be in the
// development scope, and a tier 3 change needs the computer's name, then
// its step-up.
func (ch *windowsChange) check(ctx context.Context, _ access.Caller, ts []target) error {
	for _, t := range ts {
		if !devscope.Allowed(t.org) {
			return apperr.Invalid("deviceIds", t.name+" is in an organization that is outside the development scope, where changes are not made.")
		}
	}
	if ch.tier == tierDangerous {
		if len(ts) != 1 || !strings.EqualFold(ts[0].name, ch.typed) {
			return apperr.Invalid("confirm.typed", "The name typed is not the computer's name.")
		}
		if ch.verify != nil {
			return ch.verify(ctx)
		}
	}
	return nil
}

// An apply's or undo's per-setting outcomes.
var settingOutcomes = []string{"applied", "unchanged", "skipped", "failed", "restored", "left"}

// SettingState is a setting's state in this module's result. A setting
// the result does not list, because the script left it out to keep the
// result short or because the job did not ask for it, is unknown, never in
// place: only a result that lists it can say it is.
func (f WindowsFinding) SettingState(id string) string {
	for _, s := range f.Settings {
		if s.ID == id {
			return s.State
		}
	}
	return "unknown"
}

// Complete says whether the result lists every setting it covered. When it
// does not, the caller re-runs the module alone, or the settings it needs,
// until it does.
func (f WindowsFinding) Complete() bool { return f.SettingsOmitted == "" }

// IncompleteModules are the modules of a Windows result that left settings
// out, to run again one at a time or by setting ID.
func IncompleteModules(modules []HardeningModuleResult) []string {
	var out []string
	for _, m := range modules {
		if !m.Complete() {
			out = append(out, m.Module)
		}
	}
	return out
}
