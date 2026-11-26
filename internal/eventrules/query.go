package eventrules

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrQuote is a value that holds both kinds of quote, which XPath cannot
// write.
var ErrQuote = errors.New("eventrules: a value holds both kinds of quote")

// xpathString quotes a value with whichever quote it does not hold.
func xpathString(s string) (string, error) {
	switch {
	case !strings.Contains(s, `'`):
		return "'" + s + "'", nil
	case !strings.Contains(s, `"`):
		return `"` + s + `"`, nil
	}
	return "", ErrQuote
}

func idTest(r IDRange) string {
	if r.To == 0 || r.To == r.From {
		return "EventID=" + strconv.Itoa(r.From)
	}
	return fmt.Sprintf("(EventID>=%d and EventID<=%d)", r.From, r.To)
}

func or(parts []string) string {
	if len(parts) == 1 {
		return parts[0]
	}
	return "(" + strings.Join(parts, " or ") + ")"
}

// QueryOptions are what a query of one channel adds to the input's filters.
type QueryOptions struct {
	// After is the record the page continues after: records below it for a
	// channel read newest first, above it for one read oldest first.
	After int64
	// Ascending says the channel is read oldest first (Analytic and Debug).
	Ascending bool
	// Record asks for one record only.
	Record int64
	// Now is the time relative ranges count back from.
	Now time.Time
}

// BuildQuery writes the structured query of one channel: a QueryList with
// one Select and, for the IDs to exclude, one Suppress. Within a filter the
// values are alternatives; between filters every one must hold. Values are
// quoted for XPath and the whole is escaped for XML, so a value can only be
// a value.
func BuildQuery(in Input, channel string, o QueryOptions) (string, error) {
	if err := ValidChannel(channel); err != nil {
		return "", err
	}
	var conds []string
	if o.Record > 0 {
		conds = append(conds, "EventRecordID="+strconv.FormatInt(o.Record, 10))
	}
	if in.Op == OpQuery {
		if len(in.Levels) > 0 {
			var ls []string
			for _, l := range in.Levels {
				ls = append(ls, "Level="+strconv.Itoa(l))
				if l == 4 { // Event Viewer counts Information as 0 or 4
					ls = append(ls, "Level=0")
				}
			}
			conds = append(conds, or(ls))
		}
		if len(in.IDs) > 0 {
			var ids []string
			for _, r := range in.IDs {
				ids = append(ids, idTest(r))
			}
			conds = append(conds, or(ids))
		}
		if len(in.Providers) > 0 {
			var ps []string
			for _, p := range in.Providers {
				q, err := xpathString(p)
				if err != nil {
					return "", err
				}
				ps = append(ps, "Provider[@Name="+q+"]")
			}
			conds = append(conds, or(ps))
		}
		if len(in.Tasks) > 0 {
			var ts []string
			for _, t := range in.Tasks {
				ts = append(ts, "Task="+strconv.Itoa(t))
			}
			conds = append(conds, or(ts))
		}
		if mask, ok := in.KeywordMask(); ok {
			conds = append(conds, "band(Keywords,"+strconv.FormatUint(mask, 10)+")")
		}
		if t := in.Time; t != nil {
			if d, ok := relativeRanges[t.Last]; ok {
				conds = append(conds, fmt.Sprintf("TimeCreated[timediff(@SystemTime) <= %d]", d.Milliseconds()))
			} else {
				if t.From != "" {
					from, _ := time.Parse(time.RFC3339, t.From)
					conds = append(conds, "TimeCreated[@SystemTime>='"+from.UTC().Format("2006-01-02T15:04:05.000Z")+"']")
				}
				if t.To != "" {
					to, _ := time.Parse(time.RFC3339, t.To)
					conds = append(conds, "TimeCreated[@SystemTime<='"+to.UTC().Format("2006-01-02T15:04:05.000Z")+"']")
				}
			}
		}
	}
	if o.After > 0 {
		op := "<"
		if o.Ascending {
			op = ">"
		}
		conds = append(conds, "EventRecordID"+op+strconv.FormatInt(o.After, 10))
	}
	sel := "*"
	if len(conds) > 0 {
		sel = "*[System[" + strings.Join(conds, " and ") + "]]"
	}
	var path bytes.Buffer
	if err := xml.EscapeText(&path, []byte(channel)); err != nil {
		return "", err
	}
	// The whole selection is escaped once, as XML text: the XPath reads it
	// back as written, quotes and comparison signs included.
	var selEsc bytes.Buffer
	if err := xml.EscapeText(&selEsc, []byte(sel)); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(`<QueryList><Query Id="0" Path="` + path.String() + `"><Select Path="` + path.String() + `">` + selEsc.String() + `</Select>`)
	if in.Op == OpQuery && len(in.ExcludeIDs) > 0 {
		var ids []string
		for _, r := range in.ExcludeIDs {
			ids = append(ids, idTest(r))
		}
		var sup bytes.Buffer
		if err := xml.EscapeText(&sup, []byte("*[System["+or(ids)+"]]")); err != nil {
			return "", err
		}
		b.WriteString(`<Suppress Path="` + path.String() + `">` + sup.String() + `</Suppress>`)
	}
	b.WriteString(`</Query></QueryList>`)
	return b.String(), nil
}
