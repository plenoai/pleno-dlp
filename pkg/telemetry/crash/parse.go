package crash

import (
	"errors"
	"regexp"
	"strings"
	"sync"
)

// ringSize bounds how much crash output the monitor retains. A crash
// header seen in the stream additionally pins the next ringSize bytes, so a
// fatal error whose all-goroutine dump exceeds the ring keeps its head.
const ringSize = 64 << 10

// ErrReexecFailed means the monitor could not be started; the caller
// should continue without one.
var ErrReexecFailed = errors.New("crash: re-exec failed")

// crashHeadRe finds the runtime's crash header at a line start.
var crashHeadRe = regexp.MustCompile(`(?m)^(panic: |fatal error: )`)

// parseCrash extracts the runtime crash header and the goroutine dump that
// follows it. The last header wins so CLI output that happens to contain
// "panic: " earlier is not mistaken for the crash.
func parseCrash(buf string) (Kind, string, string, bool) {
	locs := crashHeadRe.FindAllStringIndex(buf, -1)
	if len(locs) == 0 {
		return "", "", "", false
	}
	// A recovered-and-repanicked chain prints several "panic:" lines in a
	// row; start at the first header of the final contiguous block.
	start := locs[len(locs)-1][0]
	for i := len(locs) - 2; i >= 0; i-- {
		between := buf[locs[i][0]:start]
		if strings.Contains(between, "\ngoroutine ") {
			break
		}
		start = locs[i][0]
	}
	tail := buf[start:]
	kind := KindPanic
	if strings.HasPrefix(tail, "fatal error: ") {
		kind = KindFatal
	}
	g := strings.Index(tail, "\ngoroutine ")
	if g < 0 {
		return kind, strings.TrimSpace(tail), "", true
	}
	return kind, strings.TrimSpace(tail[:g]), strings.TrimLeft(tail[g:], "\n"), true
}

// ringBuffer keeps the last max bytes written to it and, from the first
// line-start crash header onward, up to max bytes of the crash dump.
type ringBuffer struct {
	mu    sync.Mutex
	max   int
	buf   []byte
	carry []byte // tail of the previous write, for headers split across writes
	crash []byte // pinned dump starting at the first crash header
}

// headerCarry is enough bytes to recognise "\nfatal error: " across writes.
const headerCarry = 16

func (r *ringBuffer) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(p)
	switch {
	case r.crash != nil:
		if room := r.max - len(r.crash); room > 0 {
			r.crash = append(r.crash, p[:min(room, n)]...)
		}
	default:
		joined := append(append([]byte{}, r.carry...), p...)
		if loc := crashHeadRe.FindIndex(joined); loc != nil &&
			(loc[0] > 0 || len(r.buf) == 0) {
			r.crash = append([]byte{}, joined[loc[0]:min(len(joined), loc[0]+r.max)]...)
		}
		r.carry = append(r.carry[:0], joined[max(0, len(joined)-headerCarry):]...)
	}
	if n >= r.max {
		r.buf = append(r.buf[:0], p[n-r.max:]...)
		return n, nil
	}
	if over := len(r.buf) + n - r.max; over > 0 {
		r.buf = append(r.buf[:0], r.buf[over:]...)
	}
	r.buf = append(r.buf, p...)
	return n, nil
}

// Crash returns the pinned dump when a header was seen, else the ring.
func (r *ringBuffer) Crash() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.crash != nil {
		return string(r.crash)
	}
	return string(r.buf)
}
