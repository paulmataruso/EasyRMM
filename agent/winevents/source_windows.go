//go:build windows

package winevents

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Channel is the one channel the Defender reader asks for.
const Channel = "Microsoft-Windows-Windows Defender/Operational"

var (
	wevtapi      = syscall.NewLazyDLL("wevtapi.dll")
	procQuery    = wevtapi.NewProc("EvtQuery")
	procNext     = wevtapi.NewProc("EvtNext")
	procRender   = wevtapi.NewProc("EvtRender")
	procClose    = wevtapi.NewProc("EvtClose")
	errNoRecords = errors.New("no records")
)

const (
	evtQueryChannelPath      = 0x1
	evtQueryForwardDirection = 0x100
	evtQueryReverse          = 0x200
	evtRenderEventXML        = 1
	errorNoMoreItems         = 259
	errorChannelNotFound     = 15007
	errorEvtChannelNotFound  = 15011
)

// DefenderSource reads Defender's Operational channel through wevtapi.
type DefenderSource struct{}

// NewDefenderSource returns the Windows reader.
func NewDefenderSource() Source { return DefenderSource{} }

func evtQuery(channel, xpath string, flags uintptr) (syscall.Handle, error) {
	c, err := syscall.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	x, err := syscall.UTF16PtrFromString(xpath)
	if err != nil {
		return 0, err
	}
	h, _, e := procQuery.Call(0, uintptr(unsafe.Pointer(c)), uintptr(unsafe.Pointer(x)), flags)
	if h == 0 {
		return 0, e
	}
	return syscall.Handle(h), nil
}

func evtClose(h syscall.Handle) { _, _, _ = procClose.Call(uintptr(h)) }

// render returns an event's XML.
func render(ev syscall.Handle) (string, error) {
	buf := make([]uint16, 4096)
	for range 2 {
		var used, props uint32
		r, _, e := procRender.Call(0, uintptr(ev), evtRenderEventXML, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return syscall.UTF16ToString(buf), nil
		}
		var errno syscall.Errno
		if errors.As(e, &errno) && errno == syscall.ERROR_INSUFFICIENT_BUFFER && int(used) > len(buf)*2 {
			buf = make([]uint16, used/2+1)
			continue
		}
		return "", e
	}
	return "", errors.New("the event is too large to render")
}

// readAll returns up to limit events of a query as XML. Events that cannot be
// rendered are skipped.
func readAll(ctx context.Context, channel, xpath string, flags uintptr, limit int) ([]string, error) {
	h, err := evtQuery(channel, xpath, flags|evtQueryChannelPath)
	if err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) && (errno == errorChannelNotFound || errno == errorEvtChannelNotFound) {
			return nil, errNoRecords
		}
		return nil, fmt.Errorf("winevents: EvtQuery: %w", err)
	}
	defer evtClose(h)
	var out []string
	for len(out) < limit {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		var handles [32]syscall.Handle
		var returned uint32
		r, _, e := procNext.Call(uintptr(h), uintptr(len(handles)), uintptr(unsafe.Pointer(&handles[0])), 1000, 0, uintptr(unsafe.Pointer(&returned)))
		if r == 0 {
			var errno syscall.Errno
			if errors.As(e, &errno) && errno == errorNoMoreItems {
				break
			}
			return out, fmt.Errorf("winevents: EvtNext: %w", e)
		}
		for i := uint32(0); i < returned; i++ {
			if len(out) < limit {
				if x, err := render(handles[i]); err == nil {
					out = append(out, x)
				}
			}
			evtClose(handles[i])
		}
	}
	return out, nil
}

func recordOf(xml string) int64 {
	e, err := Parse(xml)
	if err != nil {
		return 0
	}
	return e.RecordID
}

// Read implements Source: one query with Windows filtering on the event IDs
// and the bookmark, and two one-record queries for the channel's oldest and
// newest record (no event is rendered that is not used, beyond those two).
func (DefenderSource) Read(ctx context.Context, q Query) (Result, error) {
	var ids []string
	for _, id := range agentproto.DefenderLogEventIDs {
		ids = append(ids, fmt.Sprintf("EventID=%d", id))
	}
	cond := "(" + strings.Join(ids, " or ") + ")"
	if q.After > 0 {
		cond += fmt.Sprintf(" and EventRecordID > %d", q.After)
	}
	if !q.Since.IsZero() {
		cond += fmt.Sprintf(" and TimeCreated[timediff(@SystemTime) <= %d]", time.Since(q.Since).Milliseconds())
	}
	xpath := "*[System[" + cond + "]]"
	events, err := readAll(ctx, Channel, xpath, evtQueryForwardDirection, max(q.Limit, 1))
	if errors.Is(err, errNoRecords) {
		return Result{}, nil
	}
	if err != nil {
		return Result{}, err
	}
	res := Result{Events: events}
	if oldest, err := readAll(ctx, Channel, "*", evtQueryForwardDirection, 1); err == nil && len(oldest) == 1 {
		res.Oldest = recordOf(oldest[0])
	}
	if newest, err := readAll(ctx, Channel, "*", evtQueryReverse, 1); err == nil && len(newest) == 1 {
		res.Newest = recordOf(newest[0])
	}
	return res, nil
}

// ChannelSource reads any event channel after a record bookmark, for the log
// collector (ADR-0060): every event, rendered as XML, in record order.
type ChannelSource struct{ Name string }

// NewChannelSource returns a reader of the named channel.
func NewChannelSource(name string) Source { return ChannelSource{Name: name} }

// Read implements Source. A channel that does not exist has no events.
func (c ChannelSource) Read(ctx context.Context, q Query) (Result, error) {
	cond := "EventRecordID > 0"
	if q.After > 0 {
		cond = fmt.Sprintf("EventRecordID > %d", q.After)
	}
	if q.After == 0 && !q.Since.IsZero() {
		cond += fmt.Sprintf(" and TimeCreated[timediff(@SystemTime) <= %d]", time.Since(q.Since).Milliseconds())
	}
	events, err := readAll(ctx, c.Name, "*[System["+cond+"]]", evtQueryForwardDirection, max(q.Limit, 1))
	if errors.Is(err, errNoRecords) {
		return Result{}, nil
	}
	return Result{Events: events}, err
}
