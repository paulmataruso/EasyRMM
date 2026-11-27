package agentproto

import "time"

// Collected logs (ADR-0060, slice 2). The collector seals the events it read
// into compressed blocks in a spool; the agent sends the blocks, oldest first,
// in signed requests, and the server acknowledges the highest sequence it
// stored or knowingly refused. The agent then deletes what was acknowledged.
const (
	// PathCollectedLogs receives blocks. A server without it, or without a
	// log store, answers 404 or 503, and the agent tries again later.
	PathCollectedLogs = "/api/agent/v1/collected-logs"
	// MaxCollectedBlocks is how many blocks a request holds at most;
	// MaxCollectedBlock the largest compressed block; MaxCollectedBody the
	// largest request body the server reads (blocks travel as base64).
	MaxCollectedBlocks = 8
	MaxCollectedBlock  = 512 << 10
	MaxCollectedBody   = 8 << 20
	// CollectedEvery is how often the agent looks at its spool.
	CollectedEvery = time.Minute
)

// CollectedBlock is one block as it travels: one batch's events of one source.
type CollectedBlock struct {
	// Seq numbers the device's blocks, rising; the server stores each once.
	Seq    int64     `json:"seq"`
	Source string    `json:"source"`
	Class  string    `json:"class"`
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Count  int       `json:"count"`
	// Raw is the size of the events before compression.
	Raw   int    `json:"raw"`
	Codec string `json:"codec"`
	Data  []byte `json:"data"`
}

// CollectedBatch is what the agent sends to PathCollectedLogs.
type CollectedBatch struct {
	Blocks []CollectedBlock `json:"blocks"`
}

// CollectedAck answers a batch.
type CollectedAck struct {
	// Seq is the highest sequence the server has stored or refused for the
	// device; blocks up to it may be deleted.
	Seq int64 `json:"seq"`
	// Refused counts the blocks of the request the server did not store
	// (over the device's daily quota, or malformed).
	Refused int `json:"refused,omitempty"`
}
