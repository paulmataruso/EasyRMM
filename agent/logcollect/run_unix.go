//go:build !windows

package logcollect

import "os"

func confineOS() error { return nil }

// defaultReaders are the journal and, with the agent's socket, auditd's log.
func defaultReaders(o Options) []Reader {
	rs := []Reader{&Journal{}}
	if o.AuditSocket != "" {
		sock := o.AuditSocket
		rs = append(rs, &Audit{Close: true, Files: func() ([]*os.File, error) { return FetchAudit(sock) }})
	}
	return rs
}
