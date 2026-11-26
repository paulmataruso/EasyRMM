package dhcp

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/winmod/rolekit"
)

func addr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	return a, err == nil && a.Is4()
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func ip(p map[string]any, name string) (uint32, error) {
	a, ok := addr(rolekit.Str(p, name))
	if !ok {
		return 0, rolekit.Invalid(name, "Use an IPv4 address such as 192.0.2.10.")
	}
	return u32(a), nil
}

func guardScope(p map[string]any) error {
	_, err := ip(p, "scopeId")
	return err
}

func guardScopeAndIP(p map[string]any) error {
	if err := guardScope(p); err != nil {
		return err
	}
	_, err := ip(p, "ipAddress")
	return err
}

// guardOptionScope accepts "server" (the server-level options) or a scope ID.
func guardOptionScope(required bool) func(map[string]any) error {
	return func(p map[string]any) error {
		s := rolekit.Str(p, "scopeId")
		if s == "" && !required {
			return nil
		}
		if s == "server" {
			return nil
		}
		_, err := ip(p, "scopeId")
		return err
	}
}

func guardRange(p map[string]any) error {
	if err := guardScope(p); err != nil {
		return err
	}
	lo, err := ip(p, "startRange")
	if err != nil {
		return err
	}
	hi, err := ip(p, "endRange")
	if err != nil {
		return err
	}
	if lo > hi {
		return rolekit.Invalid("endRange", "The range ends before it starts.")
	}
	return nil
}

// maskBits returns the prefix length of a contiguous subnet mask.
func maskBits(m uint32) (int, bool) {
	n := 0
	for n < 32 && m&(1<<(31-n)) != 0 {
		n++
	}
	if n == 0 || n == 32 || m<<n != 0 {
		return 0, false
	}
	return n, true
}

func guardScopeCreate(p map[string]any) error {
	lo, err := ip(p, "startRange")
	if err != nil {
		return err
	}
	hi, err := ip(p, "endRange")
	if err != nil {
		return err
	}
	mask, err := ip(p, "subnetMask")
	if err != nil {
		return err
	}
	if _, ok := maskBits(mask); !ok {
		return rolekit.Invalid("subnetMask", "This is not a subnet mask such as 255.255.255.0.")
	}
	if lo > hi {
		return rolekit.Invalid("endRange", "The range ends before it starts.")
	}
	if lo&mask != hi&mask {
		return rolekit.Invalid("endRange", "The range must be inside one subnet.")
	}
	return nil
}

func guardScopeSet(p map[string]any) error {
	if err := guardScope(p); err != nil {
		return err
	}
	for _, k := range []string{"name", "description", "leaseHours"} {
		if _, ok := p[k]; ok {
			return nil
		}
	}
	return rolekit.Invalid("name", "Give at least one thing to change.")
}

func guardReservation(p map[string]any) error {
	if err := guardScopeAndIP(p); err != nil {
		return err
	}
	if !rolekit.MAC(rolekit.Str(p, "clientId")) {
		return rolekit.Invalid("clientId", "Use a hardware address such as 00-11-22-33-44-55.")
	}
	return nil
}

// The options the console sets by value. Options 3 (router) and 6 (DNS
// servers) reach every client and are separate, tier-3 actions; others
// (vendor classes, policies) are read only.
var (
	plainOptions   = map[int64]bool{15: true, 42: true, 51: true, 66: true, 67: true}
	networkOptions = map[int64]bool{3: true, 6: true}
	bootName       = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	bootFile       = regexp.MustCompile(`^[A-Za-z0-9._/\\-]{1,128}$`)
)

func guardOption(network bool) func(map[string]any) error {
	return func(p map[string]any) error {
		if err := guardOptionScope(true)(p); err != nil {
			return err
		}
		id, _ := rolekit.Int(p, "optionId")
		switch {
		case !network && networkOptions[id]:
			return rolekit.Refuse("use_network_option", "The gateway and DNS server options reach every client; set them with the action that asks for a step-up.")
		case !network && !plainOptions[id], network && !networkOptions[id]:
			return rolekit.Invalid("optionId", "This option cannot be set from the console.")
		}
		value := rolekit.Str(p, "value")
		switch id {
		case 3, 6, 42:
			parts := strings.Split(value, ",")
			if len(parts) > 8 {
				return rolekit.Invalid("value", "At most 8 addresses.")
			}
			for _, a := range parts {
				if _, ok := addr(strings.TrimSpace(a)); !ok {
					return rolekit.Invalid("value", "Use IPv4 addresses separated by commas.")
				}
			}
		case 15:
			if !rolekit.DNSName(value, rolekit.DNSOpts{}) {
				return rolekit.Invalid("value", "Use a domain name such as corp.example.com.")
			}
		case 51:
			n, err := strconv.Atoi(value)
			if err != nil || n < 60 || n > 31536000 || strconv.Itoa(n) != value {
				return rolekit.Invalid("value", "Use a number of seconds from 60 to 31536000.")
			}
		case 66:
			if !bootName.MatchString(value) {
				return rolekit.Invalid("value", "Use a host name or address.")
			}
		case 67:
			if !bootFile.MatchString(value) {
				return rolekit.Invalid("value", "Use a file name.")
			}
		}
		return nil
	}
}
