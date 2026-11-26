package dns

import (
	"slices"
	"strconv"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/winmod/rolekit"
)

// Protected names (ADR-0076 section 4, "Protected records"). On a domain
// these let computers find domain controllers; Active Directory itself
// changes them. The server refuses by name; the script refuses the same
// names, and the apex A, AAAA, NS and SOA records of a zone it finds in
// Active Directory, which a name cannot tell.
var (
	specialLabels = []string{"_msdcs", "domaindnszones", "forestdnszones"}
	locatorSRV    = []string{"_ldap", "_kerberos", "_kpasswd", "_gc"}
)

func labels(n string) []string {
	n = strings.ToLower(strings.TrimSuffix(n, "."))
	if n == "" {
		return nil
	}
	return strings.Split(n, ".")
}

// RelName is name relative to zone: "@" for the apex, "" when an absolute
// name (one ending in a dot) is outside the zone.
func RelName(zone, name string) string {
	z := strings.ToLower(strings.TrimSuffix(zone, "."))
	if name == "@" {
		return "@"
	}
	if !strings.HasSuffix(name, ".") {
		return name
	}
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	switch {
	case n == z:
		return "@"
	case strings.HasSuffix(n, "."+z):
		return n[:len(n)-len(z)-1]
	}
	return ""
}

func fullName(zone, rel string) string {
	z := strings.ToLower(strings.TrimSuffix(zone, "."))
	if rel == "@" {
		return z
	}
	return strings.ToLower(rel) + "." + z
}

// ProtectedRecord says whether a record name in a zone is on the protected
// list: the _msdcs, DomainDnsZones and ForestDnsZones trees, and the SRV
// names under which domain controllers are found.
func ProtectedRecord(zone, rel string) bool {
	zl := labels(zone)
	if len(zl) > 0 && slices.Contains(specialLabels, zl[0]) {
		return true
	}
	fl := labels(fullName(zone, rel))
	for _, l := range fl {
		if slices.Contains(specialLabels, l) {
			return true
		}
	}
	if len(fl) >= 2 && slices.Contains(locatorSRV, fl[0]) && (fl[1] == "_tcp" || fl[1] == "_udp") {
		return true
	}
	return len(fl) >= 1 && slices.Contains(locatorSRV, fl[0]) && slices.Contains(fl, "_sites")
}

// ProtectedZone says whether a zone is one the module never removes: the
// _msdcs zone, DomainDnsZones and ForestDnsZones. (The script also refuses
// the computer's own domain and forest root, which only it can read.)
func ProtectedZone(zone string) bool {
	zl := labels(zone)
	return len(zl) > 0 && slices.Contains(specialLabels, zl[0])
}

const (
	msgRecord = "This record helps computers find domain controllers; Active Directory maintains it, and this console does not change it."
	msgZone   = "This zone holds what Active Directory needs to find its domain controllers; this console does not remove it."
)

func checkZone(p map[string]any) error {
	if !rolekit.DNSName(rolekit.Str(p, "zone"), rolekit.DNSOpts{}) {
		return rolekit.Invalid("zone", "This is not a valid zone name.")
	}
	return nil
}

func guardZoneOnly(p map[string]any) error { return checkZone(p) }

// checkName validates the record name against the zone and returns it
// relative to the zone.
func checkName(p map[string]any) (string, error) {
	zone, name := rolekit.Str(p, "zone"), rolekit.Str(p, "name")
	if !rolekit.DNSName(name, rolekit.DNSOpts{At: true, Wildcard: true}) {
		return "", rolekit.Invalid("name", "This is not a valid record name.")
	}
	rel := RelName(zone, name)
	if rel == "" {
		return "", rolekit.Invalid("name", "The name is not inside the zone.")
	}
	return rel, nil
}

func guardRecordList(p map[string]any) error {
	if err := checkZone(p); err != nil {
		return err
	}
	if _, ok := p["name"]; ok {
		_, err := checkName(p)
		return err
	}
	return nil
}

func guardRemoveAll(p map[string]any) error {
	if err := checkZone(p); err != nil {
		return err
	}
	rel, err := checkName(p)
	if err != nil {
		return err
	}
	if rel == "@" || ProtectedRecord(rolekit.Str(p, "zone"), rel) {
		return rolekit.Refuse("protected_record", "This name is the zone apex or helps computers find domain controllers; this console does not remove it.")
	}
	return nil
}

func guardRecord(withNew bool) func(map[string]any) error {
	return func(p map[string]any) error {
		if err := checkZone(p); err != nil {
			return err
		}
		rel, err := checkName(p)
		if err != nil {
			return err
		}
		typ := rolekit.Str(p, "type")
		if err := checkData(typ, rolekit.Str(p, "data")); err != nil {
			return rolekit.Invalid("data", err.Error())
		}
		if withNew {
			if err := checkData(typ, rolekit.Str(p, "newData")); err != nil {
				return rolekit.Invalid("newData", err.Error())
			}
		}
		if typ == "CNAME" && rel == "@" {
			return rolekit.Invalid("type", "A zone's apex cannot hold a CNAME record.")
		}
		if ProtectedRecord(rolekit.Str(p, "zone"), rel) {
			return rolekit.Refuse("protected_record", msgRecord)
		}
		return nil
	}
}

type dataError string

func (e dataError) Error() string { return string(e) }

func port(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 0 && n <= 65535 && s == strconv.Itoa(n)
}

func host(s string) bool { return rolekit.DNSName(s, rolekit.DNSOpts{}) }

// checkData validates a record's canonical data text for its type.
func checkData(typ, data string) error {
	bad := dataError("This is not valid data for a " + typ + " record.")
	switch typ {
	case "A":
		if !rolekit.IPv4(data) {
			return dataError("Use an IPv4 address such as 192.0.2.10.")
		}
	case "AAAA":
		if !rolekit.IPv6(data) {
			return dataError("Use an IPv6 address.")
		}
	case "CNAME", "NS", "PTR":
		if !host(data) {
			return dataError("Use a host name such as host.example.com.")
		}
	case "MX":
		f := strings.SplitN(data, " ", 2)
		if len(f) != 2 || !port(f[0]) || !host(f[1]) {
			return dataError("Use a preference and a host name, such as 10 mail.example.com.")
		}
	case "SRV":
		f := strings.SplitN(data, " ", 4)
		if len(f) != 4 || !port(f[0]) || !port(f[1]) || !port(f[2]) || !host(f[3]) {
			return dataError("Use priority, weight, port and host, such as 0 5 5060 sip.example.com.")
		}
	case "TXT":
		if len(data) < 1 || len(data) > 255 {
			return dataError("A TXT string is 1 to 255 characters.")
		}
	default:
		return bad
	}
	return nil
}

func guardZoneCreate(p map[string]any) error {
	if err := checkZone(p); err != nil {
		return err
	}
	if ProtectedZone(rolekit.Str(p, "zone")) {
		return rolekit.Refuse("protected_zone", "This name is one Active Directory manages; this console does not create it.")
	}
	if rolekit.Str(p, "storage") == "file" && rolekit.Str(p, "dynamicUpdate") == "Secure" {
		return rolekit.Invalid("dynamicUpdate", "Secure dynamic updates need an Active Directory-integrated zone.")
	}
	return nil
}

func guardZoneRemove(p map[string]any) error {
	if err := checkZone(p); err != nil {
		return err
	}
	if ProtectedZone(rolekit.Str(p, "zone")) {
		return rolekit.Refuse("protected_zone", msgZone)
	}
	return nil
}
