//go:build windows

package logcollect

import (
	"context"
	"errors"
	"os"
)

var errNoAudit = errors.New("logcollect: auditd's log is Linux only")

// AuditFiles is Linux only.
func AuditFiles(string) ([]*os.File, error) { return nil, errNoAudit }

// ServeAudit is Linux only.
func ServeAudit(context.Context, string, func() ([]*os.File, error)) error { return errNoAudit }
