package main

import (
	"errors"
	"fmt"

	"github.com/paulmataruso/easyrmm/agent/registry"
)

// builtin runs one of the agent's builtins as the child process a job
// starts (ADR-0067). It opens no state and takes nothing from the command
// line but the builtin's name: the input and the result are files named in
// the environment.
func (e *env) builtin(args []string) error {
	if len(args) != 1 {
		return errors.New("builtin takes the name of one builtin")
	}
	switch args[0] {
	case "registry":
		return registry.Main(Version)
	}
	return fmt.Errorf("there is no builtin named %q", args[0])
}
