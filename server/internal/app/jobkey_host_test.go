package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

func TestJobKeyCommandLineIsChecked(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, args := range [][]string{
		nil, {"nonsense"}, {"rotate"}, {"rotate", "--reason"}, {"status", "extra"}, {"forget"}, {"forget", "x"},
		{"forget", "0"}, {"recover", "1", "2"}, {"finish", "extra"}, {"replace-lost", "1"}, {"rotate", "--bogus"},
	} {
		if err := JobKey(context.Background(), nil, log, args, io.Discard); !errors.Is(err, ErrJobKeyUsage) {
			t.Errorf("%v: %v", args, err)
		}
	}
}
