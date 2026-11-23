// Command stubagent stands in for MeshAgent in tests: a Windows service that
// ignores stop requests and starts a child process from its own program, as
// MeshAgent's session helpers do. Run with -kvm1 it is that child.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/sys/windows/svc"
)

type stub struct{}

func (stub) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	self, _ := os.Executable()
	child := exec.Command(self, "-kvm1")
	if err := child.Start(); err == nil {
		_ = os.WriteFile(filepath.Join(filepath.Dir(self), "child.pid"), []byte(strconv.Itoa(child.Process.Pid)), 0o600)
	}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop}
	for c := range req {
		if c.Cmd == svc.Interrogate {
			status <- c.CurrentStatus
		}
		// Stop is ignored.
	}
	return false, 0
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-kvm1" {
		time.Sleep(time.Hour)
		return
	}
	if ok, _ := svc.IsWindowsService(); ok {
		_ = svc.Run("EasyRMMMeshAgent", stub{})
		return
	}
	time.Sleep(time.Hour)
}
