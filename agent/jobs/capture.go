package jobs

import (
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// capture keeps the first and last part of a stream (ADR-0017): a script
// that prints megabytes still reports how it started and how it ended.
type capture struct {
	mu       sync.Mutex
	headSize int
	tailSize int
	head     []byte
	ring     []byte
	pos      int
	full     bool
	total    int64
}

func newCapture() *capture {
	return &capture{headSize: agentproto.StreamHead, tailSize: agentproto.StreamTail}
}

// Write never fails, so a chatty script is never blocked or killed by its
// output.
func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	c.total += int64(n)
	if room := c.headSize - len(c.head); room > 0 {
		k := min(room, len(p))
		c.head = append(c.head, p[:k]...)
		p = p[k:]
	}
	if len(p) == 0 {
		return n, nil
	}
	if c.ring == nil {
		c.ring = make([]byte, c.tailSize)
	}
	if len(p) >= c.tailSize {
		copy(c.ring, p[len(p)-c.tailSize:])
		c.pos, c.full = 0, true
		return n, nil
	}
	for len(p) > 0 {
		k := copy(c.ring[c.pos:], p)
		c.pos += k
		p = p[k:]
		if c.pos == c.tailSize {
			c.pos, c.full = 0, true
		}
	}
	return n, nil
}

// Text returns the kept output as UTF-8 without NUL, with a marker where
// bytes were dropped, and whether any were.
func (c *capture) Text() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var tail []byte
	if c.full {
		tail = append(append([]byte{}, c.ring[c.pos:]...), c.ring[:c.pos]...)
	} else if c.ring != nil {
		tail = c.ring[:c.pos]
	}
	omitted := c.total - int64(len(c.head)) - int64(len(tail))
	if omitted <= 0 {
		return clean(string(c.head) + string(tail)), false
	}
	head := c.head
	// Do not split a character at either cut.
	for i := 0; i < utf8.UTFMax && len(head) > 0; i++ {
		if r, size := utf8.DecodeLastRune(head); r != utf8.RuneError || size != 1 {
			break
		}
		head = head[:len(head)-1]
	}
	for i := 0; i < utf8.UTFMax-1 && len(tail) > 0 && !utf8.RuneStart(tail[0]); i++ {
		tail = tail[1:]
	}
	marker := fmt.Sprintf("\n\n[… %d bytes omitted …]\n\n", omitted)
	return clean(string(head) + marker + string(tail)), true
}

// clean makes output storable: valid UTF-8, no NUL, at most
// agentproto.MaxStreamBytes.
func clean(s string) string {
	s = strings.ReplaceAll(strings.ToValidUTF8(s, "�"), "\x00", "")
	if len(s) <= agentproto.MaxStreamBytes {
		return s
	}
	cut := agentproto.MaxStreamBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
