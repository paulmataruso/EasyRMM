package agentproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
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
	// of MaxStreamBytes, JSON-escaped, and a structured result of at most
	// MaxResultFile, base64-encoded (ADR-0067, Sizes).
	MaxResultBody = 8 << 20
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
	// CapJobParams is JobPayload.Params, delivered on the script's standard
	// input (ADR-0073), and JobPayloadVersionParams. A build without it
	// refuses such a job, and the server sends one only to an agent that
	// lists it.
	CapJobParams = "job.params"
	// CapJobStructured is JobPayloadVersionStructured: a payload with an
	// input, an executor, a builtin and a lane, and ResultRequest.Result
	// (ADR-0067, F2). Every kind of that sort needs it.
	CapJobStructured = "job.structured"
)

// CapBuiltin is the capability of one input version of a builtin, such as
// builtin.registry.v1 (ADR-0067). A builtin kind needs CapJobStructured and
// one of its versions.
func CapBuiltin(name string, version int) string {
	return fmt.Sprintf("builtin.%s.v%d", name, version)
}

// Executors of a structured job.
const (
	// ExecutorBuiltin is Go code in the agent's own program, run as a child
	// process of it (ADR-0067).
	ExecutorBuiltin = "builtin"
	// BuiltinRegistry is the registry editor's builtin.
	BuiltinRegistry = "registry"
	// LaneQuick marks a run of at most QuickSeconds, which the agent keeps
	// slots for beside its others.
	LaneQuick    = "quick"
	QuickSeconds = 60
)

// Bounds of structured jobs (ADR-0067, Sizes, and why one run cannot block
// a device).
const (
	// MaxInputBytes bounds a structured job's input, as JSON.
	MaxInputBytes = 1 << 20
	// MaxSignedJob bounds a signed job's real bytes: the payload as
	// SignJob base64-encodes it, with its signature.
	MaxSignedJob = 2 << 20
	// MaxAnswerBytes bounds the signed jobs of one poll answer, but for a
	// single run, which always fits.
	MaxAnswerBytes = 6 << 20
	// MaxResultFile bounds a structured result: JSON lines in a file.
	MaxResultFile = 2 << 20
	// MaxDeliveries is how many times a run is delivered without starting
	// before it fails.
	MaxDeliveries = 5
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

// JobPayloadVersion is the payload version of a job without params.
const JobPayloadVersion = 1

// JobPayloadVersionParams is the payload version of a job with params
// (ADR-0073): its signature covers the script hash and the params hash. A
// build that does not know it refuses the job instead of running it without
// its parameters.
const JobPayloadVersionParams = 2

// JobPayloadVersionStructured is the payload version of a structured job
// (ADR-0067): it carries an input and runs as a builtin, with no script and
// no shell. A build that does not know it refuses the job, which only an
// agent listing CapJobStructured is sent.
const JobPayloadVersionStructured = 3

// MaxParamsBytes bounds a job's params, in their canonical form.
const MaxParamsBytes = 16 << 10

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
	// Params is a JSON object the agent writes to the script's standard
	// input and closes (ADR-0073), in the canonical form CanonicalParams
	// gives; it may hold a secret, so nothing logs it. Only in a payload of
	// version JobPayloadVersionParams.
	Params json.RawMessage `json:"params,omitempty"`
	// ScriptSHA256 and ParamsSHA256 are the hex SHA-256 of Script and of
	// Params, which the signature covers and the agent checks. Only in a
	// payload of version JobPayloadVersionParams.
	ScriptSHA256 string `json:"scriptSha256,omitempty"`
	ParamsSHA256 string `json:"paramsSha256,omitempty"`
	// Input is the structured job's input: the exact bytes of a JSON
	// object, which the agent writes to input.json in the run's folder and
	// names in EASYRMM_JOB_INPUT. Only in a payload of version
	// JobPayloadVersionStructured; the signature covers it with the rest.
	Input []byte `json:"input,omitempty"`
	// Lane is LaneQuick or empty; Executor is ExecutorBuiltin; Builtin
	// names the builtin. Only in a structured payload.
	Lane     string `json:"lane,omitempty"`
	Executor string `json:"executor,omitempty"`
	Builtin  string `json:"builtin,omitempty"`
}

// CanonicalParams is params as the job carries and hashes them: a JSON
// object with its keys sorted and no white space. It refuses anything but an
// object, and one over MaxParamsBytes.
func CanonicalParams(params []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil || dec.More() {
		return nil, ErrJobParams
	}
	out, err := json.Marshal(m)
	if err != nil || len(out) > MaxParamsBytes {
		return nil, ErrJobParams
	}
	return out, nil
}

// HashParams is the hex SHA-256 of params in their canonical form.
func HashParams(params []byte) (string, error) {
	c, err := CanonicalParams(params)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:]), nil
}

// HashScript is the hex SHA-256 of a script body.
func HashScript(script string) string {
	sum := sha256.Sum256([]byte(script))
	return hex.EncodeToString(sum[:])
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
	// Result is a structured job's result: the JSON lines the builtin wrote
	// (a cut last line dropped), base64-encoded. Only for a job that carried
	// an input, and only to a server of level 2 or higher.
	Result string `json:"result,omitempty"`
	// ResultCut says the agent dropped result lines from the end to fit
	// MaxResultBody.
	ResultCut bool `json:"resultCut,omitempty"`
	// AgentVersion is the version of the build that ran a structured job.
	AgentVersion string `json:"agentVersion,omitempty"`
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

const (
	jobSigContext       = "EASYRMM-JOB-SIG-V1\n"
	jobSigContextParams = "EASYRMM-JOB-SIG-V2\n"
	jobSigContextStruct = "EASYRMM-JOB-SIG-V3\n"
)

// jobSigContextFor is the signature context of a payload version.
func jobSigContextFor(v int) string {
	switch v {
	case JobPayloadVersionParams:
		return jobSigContextParams
	case JobPayloadVersionStructured:
		return jobSigContextStruct
	}
	return jobSigContext
}

// Errors from VerifyJob.
var (
	ErrJobSignature = errors.New("agentproto: the job's signature does not verify with the server key this agent trusts")
	ErrJobMalformed = errors.New("agentproto: the job is malformed")
	ErrJobDevice    = errors.New("agentproto: the job is for another device")
	ErrJobExpired   = errors.New("agentproto: the job has expired")
	ErrJobParams    = errors.New("agentproto: the job's params are not a JSON object of at most 16 KiB")
	ErrJobHash      = errors.New("agentproto: the job's script or params do not match the hashes its signature covers")
	ErrJobInput     = errors.New("agentproto: the job's input is missing, or not valid for a structured job")
)

// SignJob signs a payload with the server's job key. A payload with an
// Executor becomes a JobPayloadVersionStructured one. A payload with Params
// becomes a JobPayloadVersionParams one: its params are put in canonical
// form and both hashes are set, so the signature covers them.
func SignJob(key ed25519.PrivateKey, p JobPayload) (SignedJob, error) {
	if p.Executor != "" {
		p.V = JobPayloadVersionStructured
	} else if len(p.Params) > 0 {
		c, err := CanonicalParams(p.Params)
		if err != nil {
			return SignedJob{}, err
		}
		p.V, p.Params, p.ScriptSHA256 = JobPayloadVersionParams, c, HashScript(p.Script)
		if p.ParamsSHA256, err = HashParams(c); err != nil {
			return SignedJob{}, err
		}
	}
	b, err := json.Marshal(p)
	if err != nil {
		return SignedJob{}, err
	}
	sig := ed25519.Sign(key, append([]byte(jobSigContextFor(p.V)), b...))
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
	if err != nil || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(jobSigContextFor(p.V)), b...), sig) {
		return p, ErrJobSignature
	}
	if err := checkParams(p); err != nil {
		return p, err
	}
	if p.V == JobPayloadVersionStructured {
		return p, checkStructured(p, deviceID, now)
	}
	switch {
	case (p.V != JobPayloadVersion && p.V != JobPayloadVersionParams) || p.RunID == "" || p.JobID == "" || !ValidShell(p.Shell) || p.Script == "" ||
		p.TimeoutSeconds < 1 || p.TimeoutSeconds > 4*3600 || p.PwshFallback && p.Shell != ShellPwsh ||
		len(p.Input) > 0 || p.Lane != "" || p.Executor != "" || p.Builtin != "":
		return p, ErrJobMalformed
	case p.DeviceID != deviceID:
		return p, ErrJobDevice
	case !now.Before(p.ExpiresAt):
		return p, ErrJobExpired
	}
	return p, nil
}

// checkStructured checks a structured payload (the signature is verified):
// a builtin of the agent with an input, and no script, shell or params.
func checkStructured(p JobPayload, deviceID string, now time.Time) error {
	switch {
	case p.RunID == "" || p.JobID == "" || p.TimeoutSeconds < 1 || p.TimeoutSeconds > 4*3600 ||
		p.Executor != ExecutorBuiltin || p.Builtin == "" || p.Shell != "" || p.Script != "" || len(p.Params) > 0 || p.PwshFallback ||
		p.ScriptSHA256 != "" || p.ParamsSHA256 != "" || len(p.Args) > 0:
		return ErrJobMalformed
	case len(p.Input) == 0 || len(p.Input) > MaxInputBytes:
		return ErrJobInput
	case p.Lane != "" && (p.Lane != LaneQuick || p.TimeoutSeconds > QuickSeconds):
		return ErrJobMalformed
	case p.DeviceID != deviceID:
		return ErrJobDevice
	case !now.Before(p.ExpiresAt):
		return ErrJobExpired
	}
	return nil
}

// checkParams checks what a version's payload may carry, and for a params
// one, that the script and params match the hashes the signature covers.
func checkParams(p JobPayload) error {
	switch p.V {
	case JobPayloadVersionParams:
		if len(p.Params) == 0 {
			return ErrJobMalformed
		}
		c, err := CanonicalParams(p.Params)
		if err != nil || !bytes.Equal(c, p.Params) {
			return ErrJobParams
		}
		ph, _ := HashParams(c)
		if subtle.ConstantTimeCompare([]byte(p.ParamsSHA256), []byte(ph)) != 1 ||
			subtle.ConstantTimeCompare([]byte(p.ScriptSHA256), []byte(HashScript(p.Script))) != 1 {
			return ErrJobHash
		}
	case JobPayloadVersion:
		if len(p.Params) > 0 || p.ScriptSHA256 != "" || p.ParamsSHA256 != "" {
			return ErrJobMalformed
		}
	}
	return nil
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

// ParamsPrologue is put before a PowerShell script that takes parameters
// (ADR-0073), by the Windows agent after it has verified the signed script:
// standard input and output are UTF-8 without a byte order mark. Windows
// PowerShell otherwise reads and writes the console's OEM code page, which
// would alter a name such as "José Müller" or "日本語" in either direction.
const ParamsPrologue = "[Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false\r\n"
