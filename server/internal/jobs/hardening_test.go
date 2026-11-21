package jobs

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
)

func TestHardeningScriptFitsAJob(t *testing.T) {
	if len(hardeningScript) == 0 || len(hardeningScript) > MaxJobBody {
		t.Errorf("the hardening script is %d bytes; a job carries 1 to %d", len(hardeningScript), MaxJobBody)
	}
}

func TestHardeningInput(t *testing.T) {
	valid := Hardening{
		Mode: HardeningCheck, Modules: []string{"fail2ban", "ssh", "firewall", "ssh"},
		Options: HardeningOptions{
			AllowTCP: []string{" 8080", "9000-9100", "443-443", "8080"}, AllowUDP: []string{"53"},
			Trusted: []string{"192.0.2.10", "10.1.2.3/8", "2001:db8::1/32", "192.0.2.10/32"},
			EPEL:    true, RootPasswordOff: true, PasswordOff: true,
		},
	}
	f := apperr.Fields{}
	valid.check(f)
	if err := f.Err(); err != nil {
		t.Fatal(err)
	}
	want := HardeningOptions{
		AllowTCP: []string{"8080", "9000-9100", "443"}, AllowUDP: []string{"53"},
		Trusted: []string{"192.0.2.10/32", "10.0.0.0/8", "2001:db8::/32"}, EPEL: true, RootPasswordOff: true, PasswordOff: true,
	}
	if !slices.Equal(valid.Modules, []string{"ssh", "firewall", "fail2ban"}) || !slices.Equal(valid.Options.AllowTCP, want.AllowTCP) ||
		!slices.Equal(valid.Options.AllowUDP, want.AllowUDP) || !slices.Equal(valid.Options.Trusted, want.Trusted) {
		t.Errorf("normalized %+v", valid)
	}
	if got := valid.args(); !slices.Equal(got, []string{"check", "ssh,firewall,fail2ban", "allow-tcp=8080,9000-9100,443", "allow-udp=53",
		"trusted=192.0.2.10/32,10.0.0.0/8,2001:db8::/32", "root-password-off", "password-off", "epel"}) {
		t.Errorf("args %q", got)
	}
	if l := valid.label(); l != "Check hardening: ssh, firewall, fail2ban" {
		t.Errorf("label %q", l)
	}
	all := Hardening{Mode: HardeningCheck, Modules: slices.Clone(HardeningModules)}
	if l, a := all.label(), all.args(); l != "Check hardening (every module)" || !slices.Equal(a, []string{"check", strings.Join(HardeningModules, ",")}) {
		t.Errorf("every module: %q, %q", l, a)
	}
	apply := Hardening{Mode: HardeningApply, Modules: []string{"firewall", "ssh"}, Options: HardeningOptions{AllowTCP: []string{"443"}, PasswordOff: true}}
	undo := Hardening{Mode: HardeningUndo, Modules: slices.Clone(HardeningModules)}
	for _, h := range []*Hardening{&apply, &undo} {
		f := apperr.Fields{}
		h.check(f)
		if err := f.Err(); err != nil {
			t.Fatalf("%s: %v", h.Mode, err)
		}
	}
	if l, a := apply.label(), apply.args(); l != "Apply hardening: ssh, firewall" || !slices.Equal(a, []string{"apply", "ssh,firewall", "allow-tcp=443", "password-off"}) {
		t.Errorf("apply: %q, %q", l, a)
	}
	if l, a := undo.label(), undo.args(); l != "Undo hardening (every module)" || !slices.Equal(a, []string{"undo", strings.Join(HardeningModules, ",")}) {
		t.Errorf("undo: %q, %q", l, a)
	}

	for name, c := range map[string]struct {
		h     Hardening
		field string
	}{
		"an unknown mode":          {Hardening{Mode: "harden", Modules: []string{"ssh"}}, "mode"},
		"no mode":                  {Hardening{Modules: []string{"ssh"}}, "mode"},
		"undo with ports":          {Hardening{Mode: HardeningUndo, Modules: []string{"firewall"}, Options: HardeningOptions{AllowTCP: []string{"22"}}}, "options"},
		"undo with a choice":       {Hardening{Mode: HardeningUndo, Modules: []string{"ssh"}, Options: HardeningOptions{PasswordOff: true}}, "options"},
		"no module":                {Hardening{Mode: HardeningCheck}, "modules"},
		"an unknown module":        {Hardening{Mode: HardeningCheck, Modules: []string{"ssh", "selinux; reboot"}}, "modules"},
		"all is not a module":      {Hardening{Mode: HardeningCheck, Modules: []string{"all"}}, "modules"},
		"port 0":                   {opts("firewall", HardeningOptions{AllowTCP: []string{"0"}}), "options.allowTcp"},
		"port too high":            {opts("firewall", HardeningOptions{AllowTCP: []string{"65536"}}), "options.allowTcp"},
		"a leading zero":           {opts("firewall", HardeningOptions{AllowTCP: []string{"022"}}), "options.allowTcp"},
		"a backwards range":        {opts("firewall", HardeningOptions{AllowUDP: []string{"200-100"}}), "options.allowUdp"},
		"an open range":            {opts("firewall", HardeningOptions{AllowUDP: []string{"100-"}}), "options.allowUdp"},
		"a port with a shell word": {opts("firewall", HardeningOptions{AllowTCP: []string{"22;id"}}), "options.allowTcp"},
		"too many ports":           {opts("firewall", HardeningOptions{AllowTCP: slices.Repeat([]string{"22"}, 65)}), "options.allowTcp"},
		"not an address":           {opts("fail2ban", HardeningOptions{Trusted: []string{"example.com"}}), "options.trusted"},
		"an address with a zone":   {opts("fail2ban", HardeningOptions{Trusted: []string{"fe80::1%eth0"}}), "options.trusted"},
		"an IPv4-mapped range":     {opts("fail2ban", HardeningOptions{Trusted: []string{"::ffff:10.0.0.0/104"}}), "options.trusted"},
		"too many ranges":          {opts("fail2ban", HardeningOptions{Trusted: slices.Repeat([]string{"10.0.0.0/8"}, 65)}), "options.trusted"},
		"ports without firewall":   {opts("ssh", HardeningOptions{AllowTCP: []string{"22"}}), "options.allowTcp"},
		"UDP without firewall":     {opts("ssh", HardeningOptions{AllowUDP: []string{"53"}}), "options.allowUdp"},
		"ranges without fail2ban":  {opts("ssh", HardeningOptions{Trusted: []string{"10.0.0.0/8"}}), "options.trusted"},
		"EPEL without fail2ban":    {opts("ssh", HardeningOptions{EPEL: true}), "options.epel"},
		"root without SSH":         {opts("kernel", HardeningOptions{RootPasswordOff: true}), "options.rootPasswordOff"},
		"passwords without SSH":    {opts("kernel", HardeningOptions{PasswordOff: true}), "options.passwordOff"},
	} {
		f := apperr.Fields{}
		c.h.check(f)
		if f[c.field] == "" {
			t.Errorf("%s: no %s error in %v", name, c.field, f)
		}
	}
}

func opts(module string, o HardeningOptions) Hardening {
	return Hardening{Mode: HardeningCheck, Modules: []string{module}, Options: o}
}

// result builds a result line.
func result(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return HardeningResultPrefix + string(b)
}

func TestParseHardeningResult(t *testing.T) {
	job := Hardening{Mode: HardeningCheck, Modules: []string{"ssh", "firewall"}}
	platform := map[string]any{"id": "debian", "versionId": "12", "family": "debian", "container": "none", "support": "full"}
	ssh := map[string]any{"module": "ssh", "state": "partly", "missing": []string{"LoginGraceTime 30"}, "changes": []string{"Write /etc/ssh/sshd_config.d/00-easyrmm-hardening.conf"}}
	fw := map[string]any{"module": "firewall", "state": "not_in_place", "ports": map[string]any{"tcp": []string{"22", "443"}, "unknown": []string{"nginx.service"}}}
	good := result(t, map[string]any{"version": 1, "mode": "check", "platform": platform, "modules": []any{ssh, fw}})
	r, err := parseHardeningResult("Checking ssh\nChecking firewall\n"+good+"\n\n", job)
	if err != nil {
		t.Fatal(err)
	}
	if r.Platform.ID != "debian" || len(r.Modules) != 2 || r.Modules[0].State != HardeningPartly || r.Modules[0].Missing[0] != "LoginGraceTime 30" ||
		r.Modules[1].Ports == nil || !slices.Equal(r.Modules[1].Ports.TCP, []string{"22", "443"}) {
		t.Errorf("parsed %+v", r)
	}

	with := func(change func(m map[string]any)) string {
		m := map[string]any{"version": 1, "mode": "check", "platform": platform, "modules": []any{ssh, fw}}
		change(m)
		return result(t, m)
	}
	module := func(over map[string]any) func(map[string]any) {
		return func(m map[string]any) {
			o := map[string]any{"module": "ssh", "state": "in_place"}
			for k, v := range over {
				o[k] = v
			}
			m["modules"] = []any{o, fw}
		}
	}
	long := strings.Repeat("x", maxFindingText+1)
	for name, out := range map[string]string{
		"no result":           "Checking ssh\n",
		"the result not last": good + "\nmore output\n",
		"a result too long":   HardeningResultPrefix + `{"version":1,"x":"` + strings.Repeat("y", maxHardeningResult) + `"}`,
		"not JSON":            HardeningResultPrefix + "{",
		"two values":          good + " {}",
		"an unknown field":    with(func(m map[string]any) { m["extra"] = true }),
		"version 2":           with(func(m map[string]any) { m["version"] = 2 }),
		"another mode":        with(func(m map[string]any) { m["mode"] = "apply" }),
		"an unknown family": with(func(m map[string]any) {
			m["platform"] = map[string]any{"id": "x", "versionId": "1", "family": "arch", "container": "none", "support": "full"}
		}),
		"an unknown support": with(func(m map[string]any) {
			m["platform"] = map[string]any{"id": "x", "versionId": "1", "family": "other", "container": "none", "support": "yes"}
		}),
		"no container value": with(func(m map[string]any) {
			m["platform"] = map[string]any{"id": "x", "versionId": "1", "family": "other", "support": "full"}
		}),
		"a module not asked for": with(func(m map[string]any) {
			m["modules"] = []any{ssh, fw, map[string]any{"module": "mac", "state": "in_place"}}
		}),
		"a module missing":        with(func(m map[string]any) { m["modules"] = []any{ssh} }),
		"a module twice":          with(func(m map[string]any) { m["modules"] = []any{ssh, ssh} }),
		"an unknown state":        with(module(map[string]any{"state": "hardened"})),
		"a reason too long":       with(module(map[string]any{"reason": long})),
		"a control character":     with(module(map[string]any{"reason": "a\x1b[2Jb"})),
		"an empty item":           with(module(map[string]any{"missing": []string{""}})),
		"too many items":          with(module(map[string]any{"changes": slices.Repeat([]string{"x"}, maxFindingItems+1)})),
		"an item too long":        with(module(map[string]any{"changes": []string{long}})),
		"ports on another module": with(module(map[string]any{"ports": map[string]any{"tcp": []string{"22"}}})),
		"too many ports": with(func(m map[string]any) {
			m["modules"] = []any{ssh, map[string]any{"module": "firewall", "state": "in_place", "ports": map[string]any{"udp": slices.Repeat([]string{"53"}, maxFindingItems+1)}}}
		}),
		"an outcome of a check": with(module(map[string]any{"outcome": "applied"})),
	} {
		if _, err := parseHardeningResult(out, job); !errors.Is(err, errHardeningResult) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The error is shown to people who may not read the output, so it
	// quotes nothing from it (ADR-0063).
	for _, out := range []string{
		with(func(m map[string]any) {
			m["modules"] = []any{ssh, fw, map[string]any{"module": "marker-7f3a", "state": "in_place"}}
		}),
		with(func(m map[string]any) { m["version"] = 7317 }),
	} {
		_, err := parseHardeningResult(out, job)
		if err == nil || strings.Contains(err.Error(), "marker-7f3a") || strings.Contains(err.Error(), "7317") {
			t.Errorf("error %v", err)
		}
	}
}

func TestParseHardeningOutcomes(t *testing.T) {
	platform := map[string]any{"id": "rocky", "versionId": "9.6", "family": "rhel", "container": "none", "support": "full"}
	line := func(mode string, ssh map[string]any) string {
		return result(t, map[string]any{"version": 1, "mode": mode, "platform": platform, "modules": []any{ssh}})
	}
	apply := Hardening{Mode: HardeningApply, Modules: []string{"ssh"}}
	undo := Hardening{Mode: HardeningUndo, Modules: []string{"ssh"}}
	r, err := parseHardeningResult(line("apply", map[string]any{
		"module": "ssh", "state": "in_place", "outcome": "applied", "recorded": true,
		"done": []string{"Wrote /etc/ssh/sshd_config.d/00-easyrmm-hardening.conf: MaxAuthTries 4", "Reloaded sshd.service"},
	}), apply)
	if err != nil {
		t.Fatal(err)
	}
	if m := r.Modules[0]; m.Outcome != HardeningApplied || !m.Recorded || len(m.Done) != 2 {
		t.Errorf("apply %+v", m)
	}
	r, err = parseHardeningResult(line("undo", map[string]any{
		"module": "ssh", "state": "partly", "outcome": "partly_undone", "outcomeReason": "",
		"done": []string{"Left as it is: /etc/ssh/sshd_config, which was changed after EasyRMM's apply"},
	}), undo)
	if err != nil {
		t.Fatal(err)
	}
	if m := r.Modules[0]; m.Outcome != HardeningPartlyUndone || m.Recorded {
		t.Errorf("undo %+v", m)
	}
	long := strings.Repeat("x", maxFindingText+1)
	for name, c := range map[string]struct {
		job Hardening
		out string
	}{
		"apply without an outcome":    {apply, line("apply", map[string]any{"module": "ssh", "state": "in_place"})},
		"an outcome of undo in apply": {apply, line("apply", map[string]any{"module": "ssh", "state": "in_place", "outcome": "undone"})},
		"an outcome of apply in undo": {undo, line("undo", map[string]any{"module": "ssh", "state": "in_place", "outcome": "applied"})},
		"an unknown outcome":          {undo, line("undo", map[string]any{"module": "ssh", "state": "in_place", "outcome": "reverted"})},
		"an apply result for undo":    {undo, line("apply", map[string]any{"module": "ssh", "state": "in_place", "outcome": "applied"})},
		"a reason too long": {apply, line("apply", map[string]any{
			"module": "ssh", "state": "failed", "outcome": "failed", "outcomeReason": long,
		})},
		"an empty step": {apply, line("apply", map[string]any{"module": "ssh", "state": "in_place", "outcome": "applied", "done": []string{""}})},
		"too many steps": {apply, line("apply", map[string]any{
			"module": "ssh", "state": "in_place", "outcome": "applied", "done": slices.Repeat([]string{"x"}, maxFindingItems+1),
		})},
	} {
		if _, err := parseHardeningResult(c.out, c.job); !errors.Is(err, errHardeningResult) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
