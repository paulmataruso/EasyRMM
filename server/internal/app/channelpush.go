package app

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// pushWithin bounds the work of one push. A push is never an error: whatever
// it carries is stored first, and the heartbeat or the poll finds it.
const pushWithin = 10 * time.Second

// wireChannel connects the code that decides to the agent channel's hub
// (ADR-0059, M1 to M5). Every instruction was stored by its own service
// before it is pushed; the hub sends only to a connection a signed heartbeat
// confirmed, only for an organization in the dev scope, and signs each frame.
// With the channel off it wires nothing.
func (d *Deps) wireChannel() {
	h := d.AgentChannel
	if !h.Enabled() {
		return
	}
	// Jobs: the hub claims for a confirmed connection and pushes the result.
	h.UseClaim(d.Jobs.ClaimFor)
	d.Jobs.OnWork(func(ids []uuid.UUID) {
		for _, id := range ids {
			h.Kick(id)
		}
	})
	// Logs, both ways: batches arrive through the HTTPS route's own function.
	h.UseLogBatch(func(ctx context.Context, id uuid.UUID, b agentproto.LogBatch) (*agentproto.LogAck, error) {
		ack, err := d.AgentLogs.Ingest(ctx, id, b)
		if err != nil {
			return nil, err
		}
		return &ack, nil
	})
	d.AgentLogs.OnChange(func(id uuid.UUID) {
		go d.pushLogs(id)
	})
	// Wakes: the heartbeat answer carries a removal, so the agent is asked to
	// check in, through the hub's queue (at most 100 a second).
	d.Agents.OnWake(h.Wake)
	// Repairs and settings.
	d.Recovery.OnStored(func(id uuid.UUID) { go d.pushRepair(id) })
	d.Devices.OnMovedDevices(func(ids []uuid.UUID) {
		go func() {
			for _, id := range ids {
				d.pushSettings(id)
			}
		}()
	})
}

func (d *Deps) pushLogs(id uuid.UUID) {
	ctx, cancel := context.WithTimeout(context.Background(), pushWithin)
	defer cancel()
	in, err := d.AgentLogs.Instructions(ctx, id)
	if err != nil {
		return
	}
	// An empty instruction is a message too: it ends verbose mode and following.
	d.AgentChannel.Push(id, agentproto.ChannelMessage{Type: agentproto.TypeLogs, Logs: in})
}

func (d *Deps) pushRepair(id uuid.UUID) {
	if !d.AgentChannel.Live(id) {
		return // not stored as sent: the heartbeat hands the step out
	}
	ctx, cancel := context.WithTimeout(context.Background(), pushWithin)
	defer cancel()
	if sr := d.Recovery.Pending(ctx, id); sr != nil {
		d.AgentChannel.Push(id, agentproto.ChannelMessage{Type: agentproto.TypeRepair, Repair: sr})
	}
}

func (d *Deps) pushSettings(id uuid.UUID) {
	if !d.AgentChannel.Live(id) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), pushWithin)
	defer cancel()
	s, err := d.Agents.ChannelSettings(ctx, id)
	if err != nil || s == nil {
		return
	}
	d.AgentChannel.Push(id, agentproto.ChannelMessage{Type: agentproto.TypeSettings, Settings: s})
}
