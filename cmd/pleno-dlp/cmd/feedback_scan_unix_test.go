//go:build darwin || linux

package cmd

import (
	"context"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestFeedbackScanRejectsFIFOWithoutBlocking(t *testing.T) {
	path := t.TempDir() + "/input.fifo"
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := feedbackScanMatch(context.Background(), path, "AWS", strings.Repeat("a", 64))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("FIFO error = %v, want regular-file rejection", err)
		}
	case <-time.After(time.Second):
		t.Fatal("feedback scan blocked while opening a FIFO")
	}
}
