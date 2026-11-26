//go:build windows

package winevent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/paulmataruso/easyrmm/internal/eventrules"
)

// The Windows backend: the Event Log API of wevtapi.dll, loaded lazily as
// kernel32.dll is, with no cgo. A query handle belongs to the thread that made
// it, so Run is called on a locked thread (RunFiles).

var (
	wevtapi = windows.NewLazySystemDLL("wevtapi.dll")

	procEvtQuery                      = wevtapi.NewProc("EvtQuery")
	procEvtNext                       = wevtapi.NewProc("EvtNext")
	procEvtRender                     = wevtapi.NewProc("EvtRender")
	procEvtClose                      = wevtapi.NewProc("EvtClose")
	procEvtCancel                     = wevtapi.NewProc("EvtCancel")
	procEvtOpenChannelEnum            = wevtapi.NewProc("EvtOpenChannelEnum")
	procEvtNextChannelPath            = wevtapi.NewProc("EvtNextChannelPath")
	procEvtOpenChannelConfig          = wevtapi.NewProc("EvtOpenChannelConfig")
	procEvtGetChannelConfigProperty   = wevtapi.NewProc("EvtGetChannelConfigProperty")
	procEvtOpenLog                    = wevtapi.NewProc("EvtOpenLog")
	procEvtGetLogInfo                 = wevtapi.NewProc("EvtGetLogInfo")
	procEvtOpenPublisherMetadata      = wevtapi.NewProc("EvtOpenPublisherMetadata")
	procEvtFormatMessage              = wevtapi.NewProc("EvtFormatMessage")
	procEvtGetPublisherMetadataProp   = wevtapi.NewProc("EvtGetPublisherMetadataProperty")
	procEvtGetObjectArraySize         = wevtapi.NewProc("EvtGetObjectArraySize")
	procEvtGetObjectArrayProperty     = wevtapi.NewProc("EvtGetObjectArrayProperty")
	kernel32                          = windows.NewLazySystemDLL("kernel32.dll")
	procGetDynamicTimeZoneInformation = kernel32.NewProc("GetDynamicTimeZoneInformation")
	procSystemTimeToTzSpecificLocalEx = kernel32.NewProc("SystemTimeToTzSpecificLocalTimeEx")
)

// Constants of the Event Log API (winevt.h).
const (
	evtQueryForwardDirection = 0x100
	evtQueryReverseDirection = 0x200

	evtRenderEventXML = 1

	evtOpenChannelPath = 1

	// EVT_CHANNEL_CONFIG_PROPERTY_ID
	cfgEnabled    = 0
	cfgType       = 2
	cfgClassic    = 4
	cfgRetention  = 6
	cfgAutoBackup = 7
	cfgMaxSize    = 8

	// EVT_LOG_PROPERTY_ID
	logCreation = 0
	logCount    = 5
	logOldest   = 6
	logFull     = 7
	logSize     = 3

	// EVT_FORMAT_MESSAGE_FLAGS
	fmtEvent   = 1
	fmtLevel   = 2
	fmtTask    = 3
	fmtOpcode  = 4
	fmtKeyword = 5
	fmtID      = 8

	// EVT_PUBLISHER_METADATA_PROPERTY_ID
	pubGUID      = 0
	pubLevels    = 12
	pubLevelName = 13
	pubLevelVal  = 14
	pubLevelMsg  = 15
	pubTasks     = 16
	pubTaskName  = 17
	pubTaskVal   = 19
	pubTaskMsg   = 20
	pubOpcodes   = 21
	pubOpName    = 22
	pubOpVal     = 23
	pubOpMsg     = 24
	pubKeywords  = 25
	pubKwName    = 26
	pubKwVal     = 27
	pubKwMsg     = 28

	// EVT_VARIANT_TYPE
	varString  = 1
	varUInt32  = 8
	varUInt64  = 10
	varBoolean = 13
	varGUID    = 15
	varFile    = 17
	varHandle  = 32

	// Windows error codes the engine turns into states.
	errInsufficientBuffer = 122
	errNoMoreItems        = 259
	errTimeout            = 1460
	errCancelled          = 1223
	errAccessDenied       = 5
	errServiceNotActive   = 1062
	errRPCUnavailable     = 1722
	errEvtChannelNotFound = 15007
	errEvtQueryStale      = 15011 // the existing reader treats it as "not found" too
	errEvtPublisherMeta   = 15002
	errEvtFilterTooComplx = 15026
	errEvtMsgNotFound     = 15027
	errEvtMsgIDNotFound   = 15028
	errEvtUnresolvedValue = 15029
	errEvtUnresolvedParam = 15030
	errEvtLocale          = 15033
	errEvtInvalidChannel  = 15000

	englishUS = 0x409
)

type evtVariant struct {
	Value uint64
	Count uint32
	Type  uint32
}

// errno turns a failed call's error into the code, or 0.
func errnoOf(err error) syscall.Errno {
	var e syscall.Errno
	if errors.As(err, &e) {
		return e
	}
	return 0
}

// mapErr turns a Windows error into the engine's.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	switch errnoOf(err) {
	case errEvtChannelNotFound, errEvtQueryStale, errEvtInvalidChannel:
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	case errAccessDenied:
		return fmt.Errorf("%w: %v", ErrDenied, err)
	case errCancelled:
		return ErrCancelled
	case errServiceNotActive, errRPCUnavailable:
		return fmt.Errorf("%w: %v", ErrService, err)
	case errEvtFilterTooComplx:
		return ErrTooComplex
	}
	return err
}

func call(p *windows.LazyProc, args ...uintptr) (uintptr, error) {
	r, _, e := p.Call(args...)
	if r == 0 {
		if e == nil || errnoOf(e) == 0 {
			return 0, syscall.EINVAL
		}
		return 0, e
	}
	return r, nil
}

func closeHandle(h windows.Handle) {
	if h != 0 {
		_, _, _ = procEvtClose.Call(uintptr(h))
	}
}

func u16(s string) (*uint16, error) { return windows.UTF16PtrFromString(s) }

// getVariant calls an EvtGet…Property function that fills an EVT_VARIANT
// followed by what it points to, growing the buffer once.
func getVariant(f func(size uint32, buf unsafe.Pointer, used *uint32) error) (*evtVariant, []uint64, error) {
	buf := make([]uint64, 32)
	var used uint32
	err := f(uint32(len(buf)*8), unsafe.Pointer(&buf[0]), &used)
	if errnoOf(err) == errInsufficientBuffer {
		buf = make([]uint64, int(used)/8+2)
		err = f(uint32(len(buf)*8), unsafe.Pointer(&buf[0]), &used)
	}
	if err != nil {
		return nil, nil, err
	}
	return (*evtVariant)(unsafe.Pointer(&buf[0])), buf, nil
}

// text reads a string variant: its Value is a pointer into the same buffer.
func (v *evtVariant) text(buf []uint64) string {
	if v.Type != varString || v.Value == 0 {
		return ""
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	off := uintptr(v.Value) - base
	if off >= uintptr(len(buf)*8) {
		return ""
	}
	return windows.UTF16PtrToString((*uint16)(unsafe.Add(unsafe.Pointer(&buf[0]), off)))
}

func (v *evtVariant) guid(buf []uint64) string {
	if v.Type != varGUID || v.Value == 0 {
		return ""
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	off := uintptr(v.Value) - base
	if off+16 > uintptr(len(buf)*8) {
		return ""
	}
	g := (*windows.GUID)(unsafe.Add(unsafe.Pointer(&buf[0]), off))
	return g.String()
}

func filetimeOf(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	return time.Unix(0, (int64(ft)-116444736000000000)*100).UTC()
}

type winBackend struct {
	mu        sync.Mutex
	open      map[windows.Handle]struct{}
	cancelled bool
	pubs      map[string]windows.Handle
	pubsEn    map[string]windows.Handle
	dtz       [432]byte
	haveDTZ   bool
}

// NewBackend is this computer's event logs.
func NewBackend() (Backend, error) {
	if err := wevtapi.Load(); err != nil {
		return nil, fmt.Errorf("loading wevtapi.dll: %w", err)
	}
	b := &winBackend{open: map[windows.Handle]struct{}{}, pubs: map[string]windows.Handle{}, pubsEn: map[string]windows.Handle{}}
	if r, _, _ := procGetDynamicTimeZoneInformation.Call(uintptr(unsafe.Pointer(&b.dtz[0]))); r != 0xFFFFFFFF { //nolint:gosec // a buffer of the structure's size
		b.haveDTZ = true
	}
	return b, nil
}

func (b *winBackend) Now() time.Time { return time.Now().UTC() }

// Cancel asks every open query to stop, as Microsoft describes: the
// operation returns ERROR_CANCELLED.
func (b *winBackend) Cancel() {
	b.mu.Lock()
	b.cancelled = true
	hs := make([]windows.Handle, 0, len(b.open))
	for h := range b.open {
		hs = append(hs, h)
	}
	b.mu.Unlock()
	for _, h := range hs {
		_, _, _ = procEvtCancel.Call(uintptr(h))
	}
}

func (b *winBackend) isCancelled() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cancelled
}

func (b *winBackend) CrashOnAuditFail() (int, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetIntegerValue("CrashOnAuditFail")
	if err != nil {
		return 0, false
	}
	return int(v), true
}

// Offset is the computer's offset from UTC at an instant, with its dynamic
// time zone, daylight saving included.
func (b *winBackend) Offset(t time.Time) (int, bool) {
	if !b.haveDTZ {
		return 0, false
	}
	t = t.UTC()
	utc := windows.Systemtime{Year: uint16(t.Year()), Month: uint16(t.Month()), DayOfWeek: uint16(t.Weekday()), Day: uint16(t.Day()), //nolint:gosec // calendar fields
		Hour: uint16(t.Hour()), Minute: uint16(t.Minute()), Second: uint16(t.Second())} //nolint:gosec // calendar fields
	var local windows.Systemtime
	r, _, _ := procSystemTimeToTzSpecificLocalEx.Call(uintptr(unsafe.Pointer(&b.dtz[0])), uintptr(unsafe.Pointer(&utc)), uintptr(unsafe.Pointer(&local))) //nolint:gosec // structures of the API's own sizes
	if r == 0 {
		return 0, false
	}
	l := time.Date(int(local.Year), time.Month(local.Month), int(local.Day), int(local.Hour), int(local.Minute), int(local.Second), 0, time.UTC)
	return int(l.Sub(t.Truncate(time.Second)).Seconds()), true
}

// Account looks a SID up on this computer, giving up after a moment: a domain
// account with no domain controller in reach would take far longer.
func (b *winBackend) Account(sid string) (string, bool) {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return "", false
	}
	type answer struct {
		name string
		ok   bool
	}
	ch := make(chan answer, 1)
	go func() {
		acc, dom, _, err := s.LookupAccount("")
		if err != nil {
			ch <- answer{}
			return
		}
		if dom != "" {
			acc = dom + `\` + acc
		}
		ch <- answer{acc, true}
	}()
	select {
	case a := <-ch:
		return a.name, a.ok
	case <-time.After(1500 * time.Millisecond):
		return "", false
	}
}

func (b *winBackend) channelConfig(name string) (windows.Handle, error) {
	p, err := u16(name)
	if err != nil {
		return 0, err
	}
	h, err := call(procEvtOpenChannelConfig, 0, uintptr(unsafe.Pointer(p)), 0)
	if err != nil {
		return 0, mapErr(err)
	}
	return windows.Handle(h), nil
}

func cfgProp(cfg windows.Handle, id uint32) (*evtVariant, []uint64, error) {
	return getVariant(func(size uint32, buf unsafe.Pointer, used *uint32) error {
		_, err := call(procEvtGetChannelConfigProperty, uintptr(cfg), uintptr(id), 0, uintptr(size), uintptr(buf), uintptr(unsafe.Pointer(used)))
		return err
	})
}

func logProp(log windows.Handle, id uint32) (*evtVariant, []uint64, error) {
	return getVariant(func(size uint32, buf unsafe.Pointer, used *uint32) error {
		_, err := call(procEvtGetLogInfo, uintptr(log), uintptr(id), uintptr(size), uintptr(buf), uintptr(unsafe.Pointer(used)))
		return err
	})
}

func (b *winBackend) openLog(name string) (windows.Handle, error) {
	p, err := u16(name)
	if err != nil {
		return 0, err
	}
	h, err := call(procEvtOpenLog, 0, uintptr(unsafe.Pointer(p)), evtOpenChannelPath)
	if err != nil {
		return 0, mapErr(err)
	}
	return windows.Handle(h), nil
}

var channelTypes = []string{"admin", "operational", "analytic", "debug"}

// Channels lists every channel with its configuration and, for Admin and
// Operational channels, its log's record count, size and oldest event.
func (b *winBackend) Channels(ctx context.Context) ([]eventrules.ChannelInfo, error) {
	h, err := call(procEvtOpenChannelEnum, 0, 0)
	if err != nil {
		return nil, mapErr(err)
	}
	enum := windows.Handle(h)
	defer closeHandle(enum)
	var out []eventrules.ChannelInfo
	buf := make([]uint16, 1024)
	for len(out) < eventrules.MaxChannelList {
		if ctx.Err() != nil {
			break
		}
		var used uint32
		_, err := call(procEvtNextChannelPath, uintptr(enum), uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)))
		if errnoOf(err) == errInsufficientBuffer {
			buf = make([]uint16, used+1)
			continue
		}
		if err != nil {
			if errnoOf(err) == errNoMoreItems {
				break
			}
			return out, mapErr(err)
		}
		out = append(out, b.channelInfo(windows.UTF16ToString(buf)))
	}
	return out, nil
}

func (b *winBackend) channelInfo(name string) eventrules.ChannelInfo {
	ci := eventrules.ChannelInfo{T: eventrules.LineChannel, Name: name, Type: "admin"}
	cfg, err := b.channelConfig(name)
	if err != nil {
		if errors.Is(err, ErrDenied) {
			ci.State = eventrules.StateDenied
		}
		return ci
	}
	defer closeHandle(cfg)
	if v, _, err := cfgProp(cfg, cfgType); err == nil && v.Type == varUInt32 && int(uint32(v.Value)) < len(channelTypes) { //nolint:gosec // an enum
		ci.Type = channelTypes[uint32(v.Value)] //nolint:gosec // an enum, checked above
	}
	boolOf := func(id uint32) bool {
		v, _, err := cfgProp(cfg, id)
		return err == nil && v.Type == varBoolean && uint32(v.Value) != 0 //nolint:gosec // a BOOL
	}
	ci.Enabled, ci.Classic, ci.Retention, ci.AutoBackup = boolOf(cfgEnabled), boolOf(cfgClassic), boolOf(cfgRetention), boolOf(cfgAutoBackup)
	if v, _, err := cfgProp(cfg, cfgMaxSize); err == nil && v.Type == varUInt64 {
		ci.MaxSize = int64(v.Value) //nolint:gosec // a size
	}
	if ci.Type != "admin" && ci.Type != "operational" {
		return ci
	}
	log, err := b.openLog(name)
	if err != nil {
		if errors.Is(err, ErrDenied) {
			ci.State = eventrules.StateDenied
		}
		return ci
	}
	defer closeHandle(log)
	if v, _, err := logProp(log, logCount); err == nil && v.Type == varUInt64 {
		n := int64(v.Value) //nolint:gosec // a count
		ci.Count = &n
	}
	if v, _, err := logProp(log, logSize); err == nil && v.Type == varUInt64 {
		n := int64(v.Value) //nolint:gosec // a size
		ci.Size = &n
	}
	if v, _, err := logProp(log, logFull); err == nil && v.Type == varBoolean {
		f := uint32(v.Value) != 0 //nolint:gosec // a BOOL
		ci.Full = &f
	}
	if ci.Count != nil && *ci.Count > 0 {
		if t := b.oldestEvent(name); !t.IsZero() {
			ci.Oldest = t.Format(time.RFC3339Nano)
		}
	}
	return ci
}

// oldestEvent is the time of a channel's first event, from a one-event query
// read oldest first.
func (b *winBackend) oldestEvent(name string) time.Time {
	st, err := b.Open(name, `<QueryList><Query Id="0" Path="`+xmlAttr(name)+`"><Select Path="`+xmlAttr(name)+`">*</Select></Query></QueryList>`, false)
	if err != nil {
		return time.Time{}
	}
	defer st.Close()
	batch, err := st.Next(1)
	if err != nil || len(batch.Events) == 0 {
		return time.Time{}
	}
	defer batch.Release()
	if i := strings.Index(batch.Events[0].XML, `SystemTime="`); i >= 0 {
		rest := batch.Events[0].XML[i+len(`SystemTime="`):]
		if j := strings.Index(rest, `"`); j > 0 {
			t, _ := time.Parse(time.RFC3339Nano, rest[:j])
			return t
		}
	}
	return time.Time{}
}

func xmlAttr(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// LogInfo reads a log's creation time and oldest record, and whether it is
// read oldest first.
func (b *winBackend) LogInfo(channel string) (LogInfo, error) {
	cfg, err := b.channelConfig(channel)
	if err != nil {
		return LogInfo{}, err
	}
	defer closeHandle(cfg)
	var info LogInfo
	typ := uint32(0)
	if v, _, err := cfgProp(cfg, cfgType); err == nil && v.Type == varUInt32 {
		typ = uint32(v.Value) //nolint:gosec // an enum
	}
	if typ >= 2 { // analytic or debug
		info.Ascending = true
		enabled, retention := false, false
		if v, _, err := cfgProp(cfg, cfgEnabled); err == nil && v.Type == varBoolean {
			enabled = uint32(v.Value) != 0 //nolint:gosec // a BOOL
		}
		if v, _, err := cfgProp(cfg, cfgRetention); err == nil && v.Type == varBoolean {
			retention = uint32(v.Value) != 0 //nolint:gosec // a BOOL
		}
		if enabled && !retention {
			return info, ErrAnalytic
		}
		return info, nil
	}
	log, err := b.openLog(channel)
	if err != nil {
		return info, err
	}
	defer closeHandle(log)
	if v, _, err := logProp(log, logCreation); err == nil && v.Type == varFile {
		info.Created, info.Known = filetimeOf(v.Value), true
	}
	if v, _, err := logProp(log, logOldest); err == nil && v.Type == varUInt64 {
		info.Oldest = int64(v.Value) //nolint:gosec // a record number
	}
	return info, nil
}

type winStream struct {
	b      *winBackend
	h      windows.Handle
	closed bool
}

// Open starts a structured query; the log is read newest first when reverse.
func (b *winBackend) Open(channel, queryXML string, reverse bool) (Stream, error) {
	if b.isCancelled() {
		return nil, ErrCancelled
	}
	q, err := u16(queryXML)
	if err != nil {
		return nil, err
	}
	flags := uintptr(evtQueryForwardDirection)
	if reverse {
		flags = evtQueryReverseDirection
	}
	h, err := call(procEvtQuery, 0, 0, uintptr(unsafe.Pointer(q)), flags)
	if err != nil {
		return nil, mapErr(err)
	}
	st := &winStream{b: b, h: windows.Handle(h)}
	b.mu.Lock()
	b.open[st.h] = struct{}{}
	b.mu.Unlock()
	return st, nil
}

func (s *winStream) Close() {
	if s.closed {
		return
	}
	s.closed = true
	s.b.mu.Lock()
	delete(s.b.open, s.h)
	s.b.mu.Unlock()
	closeHandle(s.h)
}

// Next reads up to n events. A wait of a second at a time lets a cancel be
// noticed between them.
func (s *winStream) Next(n int) (Batch, error) {
	var handles [batchSize]windows.Handle
	if n > batchSize {
		n = batchSize
	}
	for {
		var returned uint32
		r, _, e := procEvtNext.Call(uintptr(s.h), uintptr(n), uintptr(unsafe.Pointer(&handles[0])), 1000, 0, uintptr(unsafe.Pointer(&returned))) //nolint:gosec // an array of handles
		if r == 0 {
			switch errnoOf(e) {
			case errNoMoreItems:
				return Batch{}, io.EOF
			case errTimeout:
				if s.b.isCancelled() {
					return Batch{}, ErrCancelled
				}
				continue
			}
			return Batch{}, mapErr(e)
		}
		batch := Batch{}
		hs := append([]windows.Handle{}, handles[:returned]...)
		for _, h := range hs {
			x, err := renderXML(h)
			if err != nil {
				x = ""
			}
			h := h
			batch.Events = append(batch.Events, Raw{XML: x, Meta: func(provider string, withMessage bool) Meta { return s.b.meta(h, provider, withMessage) }})
		}
		batch.Release = func() {
			for _, h := range hs {
				closeHandle(h)
			}
		}
		return batch, nil
	}
}

// renderXML is EvtRenderEventXml: the event as Windows writes it.
func renderXML(ev windows.Handle) (string, error) {
	buf := make([]uint16, 4096)
	for range 2 {
		var used, props uint32
		r, _, e := procEvtRender.Call(0, uintptr(ev), evtRenderEventXML, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])), //nolint:gosec // a buffer
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return windows.UTF16ToString(buf), nil
		}
		if errnoOf(e) == errInsufficientBuffer && int(used) > len(buf)*2 {
			buf = make([]uint16, used/2+1)
			continue
		}
		return "", e
	}
	return "", errors.New("the event is too large to render")
}

// publisher opens a provider's metadata once per run, up to 256.
func (b *winBackend) publisher(name string, locale uint32) windows.Handle {
	cache := b.pubs
	if locale != 0 {
		cache = b.pubsEn
	}
	if h, ok := cache[name]; ok {
		return h
	}
	var h windows.Handle
	if len(cache) < 256 {
		if p, err := u16(name); err == nil {
			if r, err := call(procEvtOpenPublisherMetadata, 0, uintptr(unsafe.Pointer(p)), 0, uintptr(locale), 0); err == nil {
				h = windows.Handle(r)
			}
		}
		cache[name] = h
	}
	return h
}

// formatMessage is EvtFormatMessage with a metadata handle and an event or a
// message ID, buffers retried at the size Windows asks for.
func formatMessage(meta, ev windows.Handle, msgID uint32, flags uint32) (string, error) {
	buf := make([]uint16, 512)
	for range 3 {
		var used uint32
		r, _, e := procEvtFormatMessage.Call(uintptr(meta), uintptr(ev), uintptr(msgID), 0, 0, uintptr(flags), uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used))) //nolint:gosec // a buffer
		if r != 0 {
			if flags == fmtKeyword && int(used) <= len(buf) {
				// Keywords come as a multistring: names separated by NUL.
				return string(utf16.Decode(buf[:used])), nil
			}
			return windows.UTF16ToString(buf), nil
		}
		switch errnoOf(e) {
		case errInsufficientBuffer:
			if used > 1<<20 {
				used = 1 << 20
			}
			buf = make([]uint16, used+1)
			continue
		case errEvtUnresolvedValue, errEvtUnresolvedParam:
			// Windows returns what it could resolve, where it gives a buffer.
			return windows.UTF16ToString(buf), e
		}
		return "", e
	}
	return "", errors.New("the message is too large")
}

const noDescription = "Description unavailable: the provider's message file is not on this computer"

// meta names an event's level, task, opcode and keywords and formats its
// message, with the provider's metadata, locale 0 first and English if the
// provider has none in the computer's language.
func (b *winBackend) meta(ev windows.Handle, provider string, withMessage bool) Meta {
	var m Meta
	pm := b.publisher(provider, 0)
	if pm == 0 {
		// Forwarded events are formatted with no metadata, from their
		// RenderingInfo.
		if msg, err := formatMessage(0, ev, 0, fmtEvent); err == nil && msg != "" {
			m.Message = msg
			return m
		}
		m.MessageNote = noDescription
		return m
	}
	m.LevelName, _ = formatMessage(pm, ev, 0, fmtLevel)
	m.TaskName, _ = formatMessage(pm, ev, 0, fmtTask)
	m.OpcodeName, _ = formatMessage(pm, ev, 0, fmtOpcode)
	if kw, err := formatMessage(pm, ev, 0, fmtKeyword); err == nil || kw != "" {
		for _, k := range strings.Split(strings.Trim(kw, "\x00"), "\x00") {
			if k != "" {
				m.KeywordNames = append(m.KeywordNames, k)
			}
		}
	}
	if !withMessage {
		return m
	}
	msg, err := formatMessage(pm, ev, 0, fmtEvent)
	switch errnoOf(err) {
	case 0:
		m.Message = msg
	case errEvtLocale:
		if en := b.publisher(provider, englishUS); en != 0 {
			if msg, err2 := formatMessage(en, ev, 0, fmtEvent); err2 == nil {
				m.Message, m.MessageNote = msg, "Shown in English: the provider has no message in this computer's language"
				return m
			}
		}
		m.MessageNote = noDescription
	case errEvtUnresolvedValue, errEvtUnresolvedParam:
		m.Message, m.MessageNote = msg, "Incomplete: Windows could not resolve every insert in the message"
	case errEvtMsgNotFound, errEvtMsgIDNotFound, errEvtPublisherMeta:
		m.MessageNote = noDescription
	default:
		m.MessageNote = noDescription
	}
	return m
}

// Provider describes a provider's levels, tasks, opcodes and keywords with
// their display names.
func (b *winBackend) Provider(name string) (*eventrules.ProviderLine, error) {
	p, err := u16(name)
	if err != nil {
		return nil, err
	}
	r, err := call(procEvtOpenPublisherMetadata, 0, uintptr(unsafe.Pointer(p)), 0, 0, 0)
	if err != nil {
		if errnoOf(err) == errEvtPublisherMeta || errnoOf(err) == errEvtChannelNotFound {
			return nil, fmt.Errorf("%w: %v", ErrNotFound, err)
		}
		return nil, mapErr(err)
	}
	pm := windows.Handle(r)
	defer closeHandle(pm)
	out := &eventrules.ProviderLine{T: eventrules.LineProvider, Name: name}
	if v, buf, err := pubProp(pm, pubGUID); err == nil {
		out.GUID = v.guid(buf)
	}
	out.Levels = b.metaArray(pm, pubLevels, pubLevelName, pubLevelVal, pubLevelMsg, 0)
	out.Tasks = b.metaArray(pm, pubTasks, pubTaskName, pubTaskVal, pubTaskMsg, 0)
	out.Opcodes = b.metaArray(pm, pubOpcodes, pubOpName, pubOpVal, pubOpMsg, 16)
	out.Keywords = b.metaArray(pm, pubKeywords, pubKwName, pubKwVal, pubKwMsg, 0)
	return out, nil
}

func pubProp(pm windows.Handle, id uint32) (*evtVariant, []uint64, error) {
	return getVariant(func(size uint32, buf unsafe.Pointer, used *uint32) error {
		_, err := call(procEvtGetPublisherMetadataProp, uintptr(pm), uintptr(id), 0, uintptr(size), uintptr(buf), uintptr(unsafe.Pointer(used)))
		return err
	})
}

func arrayProp(arr windows.Handle, id, idx uint32) (*evtVariant, []uint64, error) {
	return getVariant(func(size uint32, buf unsafe.Pointer, used *uint32) error {
		_, err := call(procEvtGetObjectArrayProperty, uintptr(arr), uintptr(id), uintptr(idx), 0, uintptr(size), uintptr(buf), uintptr(unsafe.Pointer(used)))
		return err
	})
}

// metaArray reads one of the provider's arrays (levels, tasks, opcodes or
// keywords), at most 256 items; shift is the opcode's.
func (b *winBackend) metaArray(pm windows.Handle, arrID, nameID, valID, msgID, shift uint32) []eventrules.MetaItem {
	v, _, err := pubProp(pm, arrID)
	if err != nil || v.Type != varHandle {
		return nil
	}
	arr := windows.Handle(v.Value)
	defer closeHandle(arr)
	var n uint32
	if _, err := call(procEvtGetObjectArraySize, uintptr(arr), uintptr(unsafe.Pointer(&n))); err != nil {
		return nil
	}
	var out []eventrules.MetaItem
	for i := uint32(0); i < n && i < 256; i++ {
		it := eventrules.MetaItem{}
		if nv, buf, err := arrayProp(arr, nameID, i); err == nil {
			it.Name = nv.text(buf)
		}
		if vv, _, err := arrayProp(arr, valID, i); err == nil {
			switch vv.Type {
			case varUInt32:
				it.Value = uint64(uint32(vv.Value)) >> shift //nolint:gosec // a value
			case varUInt64:
				it.Value = vv.Value
			}
		}
		if mv, _, err := arrayProp(arr, msgID, i); err == nil && mv.Type == varUInt32 && uint32(mv.Value) != 0xFFFFFFFF { //nolint:gosec // a message ID
			if d, err := formatMessage(pm, 0, uint32(mv.Value), fmtID); err == nil { //nolint:gosec // a message ID
				it.Display = strings.TrimSpace(d)
			}
		}
		out = append(out, it)
	}
	return out
}
