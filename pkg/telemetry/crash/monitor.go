package crash

import (
	"errors"
	"io"
)

// MonitorMarker is the EnvChild value that marks a crash monitor process.
const MonitorMarker = "monitor"

// ErrNotMonitored means no crash monitor was started: telemetry is
// disabled, this process already is a child or monitor, or the platform
// cannot re-exec.
var ErrNotMonitored = errors.New("crash: not monitored")

// IsMonitor reports whether this process was started by StartMonitor.
func (rt *Runtime) IsMonitor() bool {
	return rt.Getenv(EnvChild) == MonitorMarker
}

// Monitor reads a runtime crash dump from r, keeping at most ringSize bytes
// of it, and passes a parsed crash through the shared redact, spool and
// opt-in upload path. args are the monitored process's arguments without
// argv[0]. It returns false when r ends without a crash header.
func (rt *Runtime) Monitor(r io.Reader, args []string) (Outcome, bool) {
	ring := &ringBuffer{max: ringSize}
	_, _ = io.Copy(ring, r)
	kind, msg, stack, ok := parseCrash(ring.Crash())
	if !ok {
		return Outcome{}, false
	}
	return rt.handle(kind, msg, stack, args), true
}
