package vmtest

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

// errStale is the runner refusing a script sent for an earlier boot.
var errStale = errors.New("the machine restarted since this script was sent; it did not run")

// channel is the host's side of the runner's protocol (runner.sh): it sends
// requests and hands each answer to the call waiting for its id.
type channel struct {
	w    io.Writer
	wsem chan struct{} // held while writing a request

	mu      sync.Mutex
	next    uint64
	waiting map[string]*pending // by request id
	err     error               // why the channel stopped; set once
}

// pending is a call waiting for an answer of one of the kinds (letters).
type pending struct {
	kinds string
	ch    chan []string
}

func newChannel(r io.Reader, w io.Writer) *channel {
	c := &channel{w: w, wsem: make(chan struct{}, 1), waiting: map[string]*pending{}}
	go c.read(bufio.NewReaderSize(r, 64<<10))
	return c
}

// read hands each answer to its caller until the stream ends. Answers no
// caller waits for (an abandoned ping, say) and lines that are not answers
// are dropped.
func (c *channel) read(r *bufio.Reader) {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = errors.New("the harness channel closed")
			}
			c.stop(err)
			return
		}
		f := strings.Split(strings.TrimSuffix(line, "\n"), " ")
		if len(f) < 2 || len(f[0]) != 1 {
			continue
		}
		c.mu.Lock()
		p := c.waiting[f[1]]
		if p != nil && strings.Contains(p.kinds, f[0]) {
			delete(c.waiting, f[1])
			p.ch <- f // buffered, and sent to once
		}
		c.mu.Unlock()
	}
}

func (c *channel) stop(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err == nil {
		c.err = err
	}
	for id, p := range c.waiting {
		close(p.ch)
		delete(c.waiting, id)
	}
}

// call sends a request and waits for its answer, whose kinds are the
// letters in answers.
func (c *channel) call(ctx context.Context, answers string, request func(id string) []byte) ([]string, error) {
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return nil, c.err
	}
	c.next++
	id := strconv.FormatUint(c.next, 10)
	ch := make(chan []string, 1)
	c.waiting[id] = &pending{kinds: answers, ch: ch}
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.waiting, id)
		c.mu.Unlock()
	}()

	if err := c.write(ctx, request(id)); err != nil {
		return nil, err
	}
	select {
	case f, ok := <-ch:
		if !ok {
			c.mu.Lock()
			defer c.mu.Unlock()
			return nil, c.err
		}
		return f, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// write sends one request. Until the runner opens its port QEMU reads
// nothing from the socket, so once the socket's buffer is full a write
// waits for the runner; ctx's end cuts it short when the writer takes
// deadlines (the harness socket does). A request cut short midway leaves
// the runner reading the rest of it, so the channel stops.
func (c *channel) write(ctx context.Context, b []byte) error {
	select {
	case c.wsem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.wsem }()
	if d, ok := c.w.(interface{ SetWriteDeadline(time.Time) error }); ok {
		cut := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			_ = d.SetWriteDeadline(time.Now())
			close(cut)
		})
		defer func() {
			if !stop() {
				<-cut
			}
			_ = d.SetWriteDeadline(time.Time{})
		}()
	}
	n, err := c.w.Write(b)
	switch {
	case err == nil:
		return nil
	case n > 0:
		err = fmt.Errorf("writing to the harness channel: %w (%d of %d bytes sent)", err, n, len(b))
		c.stop(err)
		return err
	case ctx.Err() != nil:
		return ctx.Err()
	}
	return fmt.Errorf("writing to the harness channel: %w", err)
}

// ping returns the boot id of the machine the runner answers on.
func (c *channel) ping(ctx context.Context) (string, error) {
	f, err := c.call(ctx, "P", func(id string) []byte { return []byte("P " + id + "\n") })
	if err != nil {
		return "", err
	}
	if len(f) != 3 || f[2] == "" {
		return "", fmt.Errorf("malformed answer %q", strings.Join(f, " "))
	}
	return f[2], nil
}

// result is what a script did.
type result struct {
	stdout, stderr []byte
	exit           int
}

// exec runs script on the machine whose boot id is boot, for at most
// timeout (rounded up to a second).
func (c *channel) exec(ctx context.Context, boot, script string, timeout time.Duration) (result, error) {
	secs := int64((timeout + time.Second - 1) / time.Second)
	payload := base64.StdEncoding.EncodeToString([]byte(script))
	f, err := c.call(ctx, "RE", func(id string) []byte {
		return fmt.Appendf(nil, "X %s %s %d %d\n%s\n", id, boot, max(secs, 1), len(payload), payload)
	})
	if err != nil {
		return result{}, err
	}
	switch {
	case f[0] == "E" && len(f) >= 3 && f[2] == "stale":
		return result{}, errStale
	case f[0] == "E":
		return result{}, fmt.Errorf("the runner refused the script: %s", strings.Join(f[2:], " "))
	case len(f) != 5:
		return result{}, fmt.Errorf("malformed answer with %d fields", len(f))
	}
	var r result
	if r.exit, err = strconv.Atoi(f[2]); err != nil {
		return result{}, fmt.Errorf("malformed exit code %q", f[2])
	}
	if r.stdout, err = base64.StdEncoding.DecodeString(f[3]); err != nil {
		return result{}, fmt.Errorf("malformed stdout: %w", err)
	}
	if r.stderr, err = base64.StdEncoding.DecodeString(f[4]); err != nil {
		return result{}, fmt.Errorf("malformed stderr: %w", err)
	}
	return r, nil
}
