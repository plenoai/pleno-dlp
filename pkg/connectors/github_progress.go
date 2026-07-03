// Liveness logging for the GitHub full-history scan. A large monorepo can
// legitimately spend hours inside one clone or walk with no per-repo log line;
// without a heartbeat that is indistinguishable from a hang, and the operator's
// only move is to kill a task that may have been minutes from finishing. Every
// helper here writes single-line, greppable stderr output because the scan's
// production home is a log driver that captures stderr line by line.
package connectors

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// githubHeartbeatInterval paces both the heartbeat line and the clone-progress
// throttle. One line a minute is frequent enough to bound the "is it alive?"
// question and sparse enough to stay negligible against the scan's log volume.
const githubHeartbeatInterval = 60 * time.Second

// repoHeartbeat emits a periodic liveness line for one repo scan: current
// phase (clone/walk), chunks bridged so far, heap in use, and elapsed time.
// Chunks advance only while the walk produces data, so a moving counter
// separates "slow but progressing" from "wedged"; the heap figure gives early
// warning before a memory-limit kill loses the whole repo's progress.
type repoHeartbeat struct {
	repoKey string
	start   time.Time
	phase   atomic.Value
	chunks  atomic.Int64
	stop    chan struct{}
	stopped chan struct{}
}

func startRepoHeartbeat(repoKey string, interval time.Duration) *repoHeartbeat {
	hb := &repoHeartbeat{
		repoKey: repoKey,
		start:   time.Now(),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	hb.phase.Store("clone")
	go func() {
		defer close(hb.stopped)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-hb.stop:
				return
			case <-t.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				fmt.Fprintf(os.Stderr, "github: heartbeat %s phase=%s chunks=%d heap=%s sys=%s elapsed=%s\n",
					hb.repoKey, hb.phase.Load(), hb.chunks.Load(),
					formatBytes(m.HeapAlloc), formatBytes(m.Sys),
					time.Since(hb.start).Round(time.Second))
			}
		}
	}()
	return hb
}

func (hb *repoHeartbeat) setPhase(p string) { hb.phase.Store(p) }

func (hb *repoHeartbeat) addChunk() { hb.chunks.Add(1) }

// end stops the ticker goroutine and waits for it, so a finished repo can
// never emit a stale heartbeat interleaved with the next repo's lines.
func (hb *repoHeartbeat) end() {
	close(hb.stop)
	<-hb.stopped
}

// cloneProgressWriter throttles go-git's sideband progress stream to one
// stderr line per interval. The raw stream redraws its status line with '\r'
// many times a second; only the newest snapshot has liveness value.
type cloneProgressWriter struct {
	repoKey  string
	interval time.Duration
	last     time.Time
}

func (w *cloneProgressWriter) Write(p []byte) (int, error) {
	if time.Since(w.last) >= w.interval {
		if line := lastProgressLine(p); line != "" {
			fmt.Fprintf(os.Stderr, "github: clone %s: %s\n", w.repoKey, line)
			w.last = time.Now()
		}
	}
	return len(p), nil
}

// lastProgressLine extracts the final redraw from a sideband write. Writes can
// split lines arbitrarily; a fragment like "Receiving objects: 55%" is still a
// useful snapshot, so no reassembly across writes is attempted.
func lastProgressLine(p []byte) string {
	s := strings.TrimRight(string(p), "\r\n")
	if i := strings.LastIndexAny(s, "\r\n"); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSpace(s)
}

func formatBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := uint64(unit), 0
	for u := n / unit; u >= unit; u /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
