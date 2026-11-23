package agentproto

import "time"

// Agent logs (ADR-0069, Part L). The agent keeps its own records, and new
// lines from the EasyPatch agent's log and MeshAgent's, in a file of
// limited size, and sends them in signed batches. The server acknowledges
// the highest sequence it stored, and the agent drops what was
// acknowledged.
const (
	// PathAgentLogs receives a batch of log records. A server without it
	// answers 404, and the agent tries again later.
	PathAgentLogs = "/api/agent/v1/agent-logs"
	// MaxLogBatch is how many records a batch holds at most, and
	// MaxLogBody the largest batch body the server reads.
	MaxLogBatch = 500
	MaxLogBody  = 512 << 10
	// MaxLogMessage and the other limits bound one record; the agent cuts
	// what is longer and the server does too.
	MaxLogMessage    = 8 << 10
	MaxLogAttributes = 20
	MaxLogAttrName   = 64
	MaxLogAttrValue  = 1 << 10
	// LogEvery is how often the agent sends, LogFollowEvery while someone
	// watches the device's logs.
	LogEvery       = 30 * time.Second
	LogFollowEvery = 2 * time.Second
	// MaxFollow is the longest the agent follows on the server's word, and
	// MaxVerbose the longest it logs at Debug, from the moment it learns of
	// either: a changed answer cannot keep it at either for longer.
	MaxFollow  = 15 * time.Minute
	MaxVerbose = 24 * time.Hour
)

// Sources of a record.
const (
	LogSourceAgent     = "agent"
	LogSourceEasyPatch = "easypatch"
	LogSourceMeshAgent = "meshagent"
)

// Levels of a record, lower case.
const (
	LogDebug = "debug"
	LogInfo  = "info"
	LogWarn  = "warn"
	LogError = "error"
)

// LogRecord is one log record.
type LogRecord struct {
	// Seq numbers the agent's records, rising; the server keeps one record
	// per device and sequence.
	Seq     int64             `json:"seq"`
	Time    time.Time         `json:"time"`
	Source  string            `json:"source"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Attrs   map[string]string `json:"attrs,omitempty"`
}

// LogBatch is what the agent sends to PathAgentLogs.
type LogBatch struct {
	Records []LogRecord `json:"records"`
	// Dropped counts the records dropped since the last batch the server
	// acknowledged, because the buffer was full.
	Dropped int64 `json:"dropped,omitempty"`
}

// LogInstructions tell the agent how to log. They travel in the heartbeat
// answer and the answer to a batch, as the agent's channel (ADR-0059) is
// not built; a channel would carry the same message, "logs.follow".
type LogInstructions struct {
	// VerboseUntil, when in the future (Unix seconds), has the agent log at
	// Debug until then.
	VerboseUntil int64 `json:"verboseUntil,omitempty"`
	// FollowUntil, when in the future (Unix seconds), has the agent send
	// every LogFollowEvery until then: someone is watching.
	FollowUntil int64 `json:"followUntil,omitempty"`
}

// LogAck answers a batch.
type LogAck struct {
	// Seq is the highest sequence the server has stored for the device.
	Seq  int64            `json:"seq"`
	Logs *LogInstructions `json:"logs,omitempty"`
}
