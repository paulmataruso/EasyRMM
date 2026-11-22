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
	// ShellPwsh is PowerShell 7: the newest usable machine-wide install the
	// agent finds (ADR-0064). Only an agent whose poll accepts CapJobPwsh
	// is sent one.
	ShellPwsh = "pwsh"
	// ShellCmd is the Windows command prompt: the script runs as a .cmd
	// batch file.
	ShellCmd     = "cmd"
	ShellSh      = "sh"
	ShellBash    = "bash"
	ShellPython3 = "python3"
)

// Shells lists every shell, in the order the console offers them.
var Shells = []string{ShellPowerShell, ShellPwsh, ShellCmd, ShellBash, ShellSh, ShellPython3}

// ValidShell reports whether s is a known shell.
func ValidShell(s string) bool {
	return ShellPlatforms(s) != nil
}

// ShellPlatforms says which device platforms a shell runs on.
func ShellPlatforms(shell string) []string {
	switch shell {
	case ShellPowerShell, ShellPwsh, ShellCmd:
		return []string{"windows"}
	case ShellSh, ShellBash, ShellPython3:
		return []string{"linux"}
	}
	return nil
}

// ShellRequires lists the job capabilities (PollRequest.Accepts) an agent
// must accept to be sent a job in the shell: none for the shells every
// agent runs.
func ShellRequires(shell string) []string {
	if shell == ShellPwsh {
		return []string{CapJobPwsh}
	}
	return []string{}
}

// Job capabilities an agent lists in PollRequest.Accepts (ADR-0064).
const (
	// CapJobPwsh is the pwsh shell, JobPayload.PwshFallback and
	// ResultRequest.Interpreter.
	CapJobPwsh = "job.pwsh"
)

// MaxAccepts bounds the capabilities a poll lists, and MaxAcceptLen each
// one's length.
const (
	MaxAccepts   = 32
	MaxAcceptLen = 64
)

// Run statuses an agent reports.
const (
	RunSucceeded = "succeeded"
	RunFailed    = "failed"
	RunTimedOut  = "timed_out"
	RunCanceled  = "canceled"
)

// PollRequest asks for work.
type PollRequest struct {
	// Accepts lists the job capabilities this build takes (CapJobPwsh…):
	// a general list, for every instruction a poll may bring. Added after
	// protocol level 2 (ADR-0009): the agent sends it only while its last
	// heartbeat answer was of level 2 or higher. Nil (absent) says nothing
	// and leaves what the server keeps; an empty list says "none".
	Accepts []string `json:"accepts,omitzero"`
}

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
	// PwshFallback lets a pwsh script run in Windows PowerShell 5.1 where
	// no usable PowerShell 7 is found; without it the run fails there. Only
	// for ShellPwsh, so only to an agent that accepts CapJobPwsh: a build
	// before it refuses the field (ADR-0009).
	PwshFallback bool `json:"pwshFallback,omitempty"`
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
	// Interpreter is the program the agent started, read from it just
	// before (ADR-0064); nil when nothing was started. Added after protocol
	// level 2: sent only to a server of level 2 or higher.
	Interpreter *Interpreter `json:"interpreter,omitempty"`
}

// Editions of PowerShell, as $PSVersionTable.PSEdition names them.
const (
	// EditionDesktop is Windows PowerShell 5.1.
	EditionDesktop = "Desktop"
	// EditionCore is PowerShell 7 and later.
	EditionCore = "Core"
)

// Architectures of a program, from its PE header.
const (
	ArchX64   = "x64"
	ArchARM64 = "arm64"
	ArchX86   = "x86"
)

// Interpreter is the program a run started. cmd and the Linux shells give
// the path only.
type Interpreter struct {
	// Edition is EditionDesktop or EditionCore for PowerShell, else empty.
	Edition string `json:"edition,omitempty"`
	// Version is the product version, with a prerelease label for a
	// preview (7.6.0-preview.4); for Windows PowerShell, the registry's
	// major and minor with its engine's build and revision, as
	// $PSVersionTable.PSVersion gives it.
	Version string `json:"version,omitempty"`
	// Arch is ArchX64, ArchARM64 or ArchX86, from the program's PE header.
	Arch string `json:"arch,omitempty"`
	Path string `json:"path"`
	// Fallback says a pwsh script ran in Windows PowerShell 5.1, as it
	// allows, because no usable PowerShell 7 was found.
	Fallback bool `json:"fallback,omitempty"`
}

// Bounds of an Interpreter's text, as the server keeps it.
const (
	MaxInterpreterVersion = 64
	MaxInterpreterPath    = 520
)

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
		p.TimeoutSeconds < 1 || p.TimeoutSeconds > 4*3600 || p.PwshFallback && p.Shell != ShellPwsh:
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
