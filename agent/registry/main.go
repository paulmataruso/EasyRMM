package registry

import (
	"errors"
	"fmt"
	"os"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Main is the builtin's entry point: "easyrmm-agent builtin registry". It
// reads the typed input from the file named by EASYRMM_JOB_INPUT, writes its
// result lines to the file named by EASYRMM_JOB_RESULT, and prints only
// diagnostics. The input is decoded strictly and checked again here, against
// the rules this build was made with.
func Main(version string) error {
	in, out := os.Getenv("EASYRMM_JOB_INPUT"), os.Getenv("EASYRMM_JOB_RESULT")
	if in == "" || out == "" {
		return errors.New("the registry builtin is started by the agent, with EASYRMM_JOB_INPUT and EASYRMM_JOB_RESULT set")
	}
	return RunFiles(in, out, version, nil)
}

// RunFiles is Main with the files named and, for tests, a Backend; nil
// opens the machine's registry.
func RunFiles(inputPath, resultPath, version string, be Backend) error {
	raw, err := os.ReadFile(inputPath) //nolint:gosec // named by the agent in the run's environment
	if err != nil {
		return fmt.Errorf("reading the input: %w", err)
	}
	if len(raw) > agentproto.MaxInputBytes {
		return errors.New("the input is too large")
	}
	input, err := agentproto.DecodeRegistryInput(raw)
	if err != nil {
		return err
	}
	if be == nil {
		if be, err = NewBackend(); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(resultPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // named by the agent in the run's environment
	if err != nil {
		return fmt.Errorf("opening the result file: %w", err)
	}
	runErr := Run(input, be, f, Options{AgentVersion: version})
	if cerr := f.Close(); runErr == nil {
		runErr = cerr
	}
	return runErr
}
