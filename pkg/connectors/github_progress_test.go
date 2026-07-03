package connectors

import (
	"testing"
	"time"
)

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0B"},
		{512, "512B"},
		{1024, "1.0KiB"},
		{1536, "1.5KiB"},
		{2761134080, "2.6GiB"},
	}
	for _, c := range cases {
		if got := formatBytes(c.in); got != c.want {
			t.Errorf("formatBytes(%d) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestLastProgressLine(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Counting objects: 10%\rCounting objects: 55%\r", "Counting objects: 55%"},
		{"remote: Enumerating objects: 100, done.\n", "remote: Enumerating objects: 100, done."},
		{"\r\n", ""},
		{"partial fragment", "partial fragment"},
	}
	for _, c := range cases {
		if got := lastProgressLine([]byte(c.in)); got != c.want {
			t.Errorf("lastProgressLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCloneProgressWriterThrottles(t *testing.T) {
	w := &cloneProgressWriter{repoKey: "o/r", interval: time.Hour}
	if n, err := w.Write([]byte("Receiving objects: 10%\r")); err != nil || n != 23 {
		t.Fatalf("first write: n=%d err=%v", n, err)
	}
	first := w.last
	if first.IsZero() {
		t.Fatal("first write should emit and stamp last")
	}
	if _, err := w.Write([]byte("Receiving objects: 20%\r")); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if w.last != first {
		t.Error("second write within interval should be suppressed")
	}
}

func TestRepoHeartbeatEndStopsGoroutine(t *testing.T) {
	hb := startRepoHeartbeat("o/r", time.Hour)
	hb.setPhase("walk")
	hb.addChunk()
	done := make(chan struct{})
	go func() {
		hb.end()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat goroutine did not stop")
	}
	if hb.chunks.Load() != 1 {
		t.Errorf("chunks = %d, want 1", hb.chunks.Load())
	}
}
