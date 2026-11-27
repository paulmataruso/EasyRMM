//go:build !windows

package winevents

import (
	"context"
	"errors"
)

// Channel is the one channel the Defender reader asks for.
const Channel = "Microsoft-Windows-Windows Defender/Operational"

type unsupported struct{}

func (unsupported) Read(context.Context, Query) (Result, error) {
	return Result{}, errors.New("winevents: the Windows event log is read on Windows only")
}

// NewDefenderSource returns a source that refuses, off Windows.
func NewDefenderSource() Source { return unsupported{} }

// NewChannelSource returns a source that refuses, off Windows.
func NewChannelSource(string) Source { return unsupported{} }
