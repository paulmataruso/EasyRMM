package agentproto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Job delivery (ADR-0017).
const (
	// PathJobsPoll is the long poll for jobs and cancellations.
	PathJobsPoll = "/api/agent/v1/jobs/poll"
	// PollWait is how long the server holds a poll without work.
	PollWait = 25 * time.Second
	// MaxPollJobs bounds the jobs in one poll answer.
	MaxPollJobs = 8
	// MaxResultBody is the largest result body the server reads: two streams
	// of MaxStreamBytes, JSON-escaped, and room to spare.
	MaxResultBody = 4 << 20
	// StreamHead and StreamTail are how much of each output stream the agent
	// keeps from its start and its end.
	StreamHead = 128 << 10
	StreamTail = 128 << 10
	// MaxStreamBytes is the longest stream a result may carry: head, tail
	// and the marker between them.
	MaxStreamBytes = StreamHead + StreamTail + 1024
	// MaxJobError bounds a run's error text.
	MaxJobError = 2000
)

// PathJobStart is where the agent asks to start a run.
func PathJobStart(runID string) string { return "/api/agent/v1/jobs/" + runID + "/start" }

// PathJobResult is where the agent reports a run's result.
func PathJobResult(runID string) string { return "/api/agent/v1/jobs/" + runID + "/result" }

// Shells the agent can run scripts with.
const (
	// ShellPowerShell is Windows PowerShell 5.1, built into Windows.
	ShellPowerShell = "powershell"
	// ShellCmd is the Windows command prompt: the script runs as a .cmd
	// batch file.
	ShellCmd     = "cmd"
	ShellSh      = "sh"
	ShellBash    = "bash"
	ShellPython3 = "python3"
)

// Shells lists every shell, in the order the console offers them.
var Shells = []string{ShellPowerShell, ShellCmd, ShellBash, ShellSh, ShellPython3}

// ValidShell reports whether s is a known shell.
func ValidShell(s string) bool {
	return ShellPlatforms(s) != nil
}

// ShellPlatforms says which device platforms a shell runs on.
func ShellPlatforms(shell string) []string {
	switch shell {
	case ShellPowerShell, ShellCmd:
		return []string{"windows"}
	case ShellSh, ShellBash, ShellPython3:
		return []string{"linux"}
	}
	return nil
}

// Run statuses an agent reports.
const (
	RunSucceeded = "succeeded"
	RunFailed    = "failed"
	RunTimedOut  = "timed_out"
	RunCanceled  = "canceled"
)

// PollRequest asks for work.
type PollRequest struct{}

// PollResponse carries new jobs and the runs to stop.
type PollResponse struct {
	Jobs []SignedJob `json:"jobs"`
	// Cancel lists running runs the agent should stop.
	Cancel []string `json:"cancel"`
}

// SignedJob is a job payload and the server's signature over it.
type SignedJob struct {
	// Payload is the JobPayload JSON, base64 (standard, padded).
	Payload string `json:"payload"`
	// Signature is the Ed25519 signature, base64 (standard, padded).
	Signature string `json:"signature"`
}

// JobPayloadVersion is the payload version this code writes and reads.
const JobPayloadVersion = 1

// JobPayload is what the server asks a device to run.
type JobPayload struct {
	V              int       `json:"v"`
	RunID          string    `json:"runId"`
	JobID          string    `json:"jobId"`
	DeviceID       string    `json:"deviceId"`
	Shell          string    `json:"shell"`
	Script         string    `json:"script"`
	Args           []string  `json:"args"`
	TimeoutSeconds int       `json:"timeoutSeconds"`
	IssuedAt       time.Time `json:"issuedAt"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

// StartResponse says whether the agent may run the job.
type StartResponse struct {
	Proceed bool `json:"proceed"`
}

// ResultRequest reports how a run ended.
type ResultRequest struct {
	// Status is RunSucceeded, RunFailed, RunTimedOut or RunCanceled.
	Status string `json:"status"`
	// ExitCode is nil when the process did not exit by itself.
	ExitCode        *int      `json:"exitCode"`
	Stdout          string    `json:"stdout"`
	Stderr          string    `json:"stderr"`
	StdoutTruncated bool      `json:"stdoutTruncated"`
	StderrTruncated bool      `json:"stderrTruncated"`
	Error           string    `json:"error"`
	StartedAt       time.Time `json:"startedAt,omitzero"`
	FinishedAt      time.Time `json:"finishedAt,omitzero"`
}

const jobSigContext = "EASYRMM-JOB-SIG-V1\n"

// Errors from VerifyJob.
var (
	ErrJobSignature = errors.New("agentproto: the job's signature does not verify with the server key this agent trusts")
	ErrJobMalformed = errors.New("agentproto: the job is malformed")
	ErrJobDevice    = errors.New("agentproto: the job is for another device")
	ErrJobExpired   = errors.New("agentproto: the job has expired")
)

// SignJob signs a payload with the server's job key.
func SignJob(key ed25519.PrivateKey, p JobPayload) (SignedJob, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return SignedJob{}, err
	}
	sig := ed25519.Sign(key, append([]byte(jobSigContext), b...))
	return SignedJob{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// DecodeJob reads a signed job's payload without checking the signature, so
// an agent can report a job it refuses against the right run.
func DecodeJob(j SignedJob) (JobPayload, []byte, error) {
	b, err := base64.StdEncoding.DecodeString(j.Payload)
	if err != nil {
		return JobPayload{}, nil, ErrJobMalformed
	}
	var p JobPayload
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return JobPayload{}, nil, ErrJobMalformed
	}
	return p, b, nil
}

// VerifyJob checks a signed job with the pinned server key and returns its
// payload. It refuses jobs for other devices and expired jobs.
func VerifyJob(key ed25519.PublicKey, j SignedJob, deviceID string, now time.Time) (JobPayload, error) {
	p, b, err := DecodeJob(j)
	if err != nil {
		return JobPayload{}, err
	}
	sig, err := base64.StdEncoding.DecodeString(j.Signature)
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(jobSigContext), b...), sig) {
		return p, ErrJobSignature
	}
	switch {
	case p.V != JobPayloadVersion || p.RunID == "" || p.JobID == "" || !ValidShell(p.Shell) || p.Script == "" ||
		p.TimeoutSeconds < 1 || p.TimeoutSeconds > 4*3600:
		return p, ErrJobMalformed
	case p.DeviceID != deviceID:
		return p, ErrJobDevice
	case !now.Before(p.ExpiresAt):
		return p, ErrJobExpired
	}
	return p, nil
}

// EncodeKey is the text form of a job-signing public key.
func EncodeKey(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }

// DecodeKey reads a job-signing public key.
func DecodeKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("agentproto: %q is not an Ed25519 public key", s)
	}
	return ed25519.PublicKey(b), nil
}
