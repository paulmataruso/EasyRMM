// Package auditfwd forwards the audit log to a syslog collector (ADR-0023):
// every record, in order, as an RFC 5424 message whose text is the record
// in JSON, over UDP (RFC 5426), TCP (RFC 6587, octet counting) or TLS
// (RFC 5425).
package auditfwd

import (
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/paulmataruso/easyrmm/server/internal/audit"
)

// Facilities are the RFC 5424 facilities an administrator can choose: auth
// (4), authpriv (10), log audit (13, the default) and local0 to local7.
var Facilities = []int{4, 10, 13, 16, 17, 18, 19, 20, 21, 22, 23}

// DefaultFacility is "log audit".
const DefaultFacility = 13

const (
	appName = "easyrmm"
	// maxDatagram bounds a UDP message. RFC 5426 receivers must take 480
	// octets and should take 2048; common collectors take 8 KiB (rsyslog's
	// default). Larger records go without their details.
	maxDatagram = 8 << 10
	// maxFrame bounds a TCP or TLS message. Audit details are at most 16 KiB,
	// so no record comes near it.
	maxFrame = 64 << 10
)

// record is an audit record as forwarded: the console API's form plus the
// hash chain, so that a collector can check that nothing is missing or
// altered.
type record struct {
	audit.Entry
	PrevHash  string `json:"prevHash,omitempty"`
	EntryHash string `json:"entryHash"`
}

// stored is a record read from the database.
type stored struct {
	audit.Entry
	prevHash, entryHash []byte
}

func (s stored) record() record {
	r := record{Entry: s.Entry, EntryHash: hex.EncodeToString(s.entryHash)}
	if len(s.prevHash) > 0 {
		r.PrevHash = hex.EncodeToString(s.prevHash)
	}
	if r.Details == nil {
		r.Details = map[string]any{}
	}
	return r
}

// formatter builds RFC 5424 messages for one server.
type formatter struct {
	facility int
	hostname string
	sd       string
}

func newFormatter(facility int, hostname, version string) formatter {
	if version == "" {
		version = "dev"
	}
	if len(version) > 48 {
		version = version[:48]
	}
	return formatter{
		facility: facility,
		hostname: headerField(hostname, 255),
		sd:       `[origin software="EasyRMM" swVersion="` + sdEscape(version) + `"]`,
	}
}

// severity maps an outcome to an RFC 5424 severity: informational for
// success, notice for failure, warning for denied.
func severity(o audit.Outcome) int {
	switch o {
	case audit.Success:
		return 6
	case audit.Failure:
		return 5
	default:
		return 4
	}
}

// message formats a record, leaving out its details when the message would
// exceed limit.
func (f formatter) message(s stored, limit int) ([]byte, error) {
	r := s.record()
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	m := f.format(r.OccurredAt, severity(r.Outcome), r.Action, body)
	if len(m) <= limit {
		return m, nil
	}
	size := len(body)
	r.Details = map[string]any{"truncated": true, "size": size}
	if len(r.UserAgent) > 256 {
		r.UserAgent = r.UserAgent[:256]
	}
	if body, err = json.Marshal(r); err != nil {
		return nil, err
	}
	return f.format(r.OccurredAt, severity(r.Outcome), r.Action, body), nil
}

// format writes HEADER SP STRUCTURED-DATA SP MSG. MSG is JSON without a
// byte order mark (RFC 5424's MSG-ANY), which is what collectors that parse
// JSON expect.
func (f formatter) format(at time.Time, sev int, msgID string, body []byte) []byte {
	var b strings.Builder
	b.Grow(len(body) + 160)
	b.WriteByte('<')
	b.WriteString(strconv.Itoa(f.facility*8 + sev))
	b.WriteString(">1 ")
	b.WriteString(at.UTC().Format("2006-01-02T15:04:05.000000Z07:00"))
	b.WriteByte(' ')
	b.WriteString(f.hostname)
	b.WriteString(" " + appName + " - ")
	b.WriteString(headerField(msgID, 32))
	b.WriteByte(' ')
	b.WriteString(f.sd)
	b.WriteByte(' ')
	b.Write(body)
	return []byte(b.String())
}

// headerField makes s a valid header field: printable US-ASCII without
// spaces, at most n characters, or "-" (the nil value) when empty.
func headerField(s string, n int) string {
	out := make([]byte, 0, min(len(s), n))
	for i := 0; i < len(s) && len(out) < n; i++ {
		c := s[i]
		if c < 33 || c > 126 {
			c = '_'
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return "-"
	}
	return string(out)
}

// sdEscape escapes a structured data parameter value.
func sdEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(s)
}

// frame wraps a message for a stream transport with octet counting
// (RFC 6587 section 3.4.1, RFC 5425 section 4.3).
func frame(m []byte) []byte {
	out := strconv.AppendInt(nil, int64(len(m)), 10)
	out = append(out, ' ')
	return append(out, m...)
}
