package logcollect

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// SendFunc sends a batch of blocks, signed, and returns the server's answer.
// It returns ErrUnsupported for a server that stores no collected logs.
type SendFunc func(ctx context.Context, b agentproto.CollectedBatch) (agentproto.CollectedAck, error)

// ErrUnsupported is the answer of a server without a log store.
var ErrUnsupported = errors.New("logcollect: the server takes no collected logs")

// Uploader sends the spool's blocks, oldest first, and deletes what the
// server acknowledged. It runs in the agent, which holds the device's key; the
// collector never sends.
type Uploader struct {
	Spool *Spool
	Send  SendFunc
	Log   *slog.Logger
	// Every is how often the spool is looked at; Backoff how long to wait
	// after a failure or an unsupporting server.
	Every, Backoff time.Duration
}

func (u *Uploader) log() *slog.Logger {
	if u.Log != nil {
		return u.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Once sends every pending block, up to MaxCollectedBlocks per request, and
// returns how many blocks the server acknowledged.
func (u *Uploader) Once(ctx context.Context) (int, error) {
	total := 0
	for ctx.Err() == nil {
		blocks, err := u.Spool.Pending(agentproto.MaxCollectedBlocks)
		if err != nil {
			return total, err
		}
		if len(blocks) == 0 {
			return total, nil
		}
		ack, err := u.Send(ctx, agentproto.CollectedBatch{Blocks: blocks})
		if err != nil {
			return total, err
		}
		if ack.Seq < blocks[0].Seq {
			return total, errors.New("logcollect: the server acknowledged nothing")
		}
		if err := u.Spool.Ack(ack.Seq); err != nil {
			return total, err
		}
		for _, b := range blocks {
			if b.Seq <= ack.Seq {
				total++
			}
		}
		if ack.Refused > 0 {
			u.log().Warn("the server refused collected log blocks", "refused", ack.Refused)
		}
	}
	return total, ctx.Err()
}

// Run uploads until ctx ends.
func (u *Uploader) Run(ctx context.Context) {
	every, backoff := u.Every, u.Backoff
	if every <= 0 {
		every = agentproto.CollectedEvery
	}
	if backoff <= 0 {
		backoff = 10 * time.Minute
	}
	wait := every
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = every
		if _, err := u.Once(ctx); err != nil && ctx.Err() == nil {
			wait = backoff
			if !errors.Is(err, ErrUnsupported) {
				u.log().Warn("uploading collected logs failed; trying again later", "error", err)
			}
		}
	}
}
