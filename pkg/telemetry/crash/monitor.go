package crash

import (
	"errors"
	"io"
	"strings"
)

// MonitorMarker is the EnvChild value that marks a crash monitor process.
const MonitorMarker = "monitor"

// fatalNoHeader is the message of a fatal error whose header line did not
// reach the crash output.
const fatalNoHeader = "fatal error: (message not captured)"

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
// argv[0]. It returns false when r ends without a crash dump.
func (rt *Runtime) Monitor(r io.Reader, args []string) (Outcome, bool) {
	ring := &ringBuffer{max: ringSize}
	_, _ = io.Copy(ring, r)
	dump := ring.Crash()
	kind, msg, stack, ok := parseCrash(dump)
	if !ok {
		// The runtime prints a fatal error's header before it starts
		// copying to the crash output, so only the dump arrives.
		g := strings.Index(dump, "goroutine ")
		if g < 0 || (g > 0 && dump[g-1] != '\n') {
			return Outcome{}, false
		}
		kind, msg, stack = KindFatal, fatalNoHeader, dump[g:]
	}
	return rt.handle(kind, msg, stack, args), true
}
