package crash

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/plenoai/pleno-dlp/pkg/telemetry/report"
)

// ringSize bounds how much child stderr the supervisor retains. A crash
// header seen in the stream additionally pins the next ringSize bytes, so a
// fatal error whose all-goroutine dump exceeds the ring keeps its head.
const ringSize = 64 << 10

var (
	// ErrNotSupervised means the caller should run the CLI in-process:
	// telemetry is disabled or this process already is the child.
	ErrNotSupervised = errors.New("crash: not supervised")
	// ErrReexecFailed means the child could not be started; the caller
	// should fall back to running in-process.
	ErrReexecFailed = errors.New("crash: re-exec failed")
)

// crashHeadRe finds the runtime's crash header at a line start.
var crashHeadRe = regexp.MustCompile(`(?m)^(panic: |fatal error: )`)

// Supervise re-executes the binary as a child when crash reports are
// enabled, tees its stderr into a ring buffer, and reports a Go runtime
// crash after the child exits. It returns the exit code the parent must
// exit with. When disabled it returns ErrNotSupervised without starting a
// process, so the default path costs one config read.
func (rt *Runtime) Supervise(ctx context.Context, argv, env []string) (int, error) {
	if rt.Getenv(EnvChild) != "" {
		return 0, ErrNotSupervised
	}
	cfg, err := report.Load(rt.Getenv)
	if err != nil || !cfg.Enabled {
		return 0, ErrNotSupervised
	}
	exe, err := rt.Executable()
	if err != nil {
		return 0, errors.Join(ErrReexecFailed, err)
	}
	ring := &ringBuffer{max: ringSize}
	child := exec.Command(exe, argv[1:]...)
	child.Args[0] = argv[0]
	child.Env = append(append([]string{}, env...), EnvChild+"=1")
	child.Stdin, child.Stdout = os.Stdin, os.Stdout
	child.Stderr = io.MultiWriter(rt.Stderr, ring)

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	if err := child.Start(); err != nil {
		return 0, errors.Join(ErrReexecFailed, err)
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				_ = child.Process.Signal(s)
			case <-ctx.Done():
				_ = child.Process.Signal(os.Interrupt)
				<-done
				return
			case <-done:
				return
			}
		}
	}()
	waitErr := child.Wait()
	close(done)

	code := exitCode(child.ProcessState, waitErr)
	if code == 2 {
		if kind, msg, stack, ok := parseCrash(ring.Crash()); ok {
			rt.handle(kind, msg, stack, argv[1:])
		}
	}
	return code, nil
}

// exitCode maps the child's termination to a shell-style status.
func exitCode(ps *os.ProcessState, waitErr error) int {
	if ps == nil {
		if waitErr != nil {
			return 1
		}
		return 0
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}

// parseCrash extracts the runtime crash header and the goroutine dump that
// follows it. The last header wins so CLI output that happens to contain
// "panic: " earlier is not mistaken for the crash.
func parseCrash(buf string) (report.CrashKind, string, string, bool) {
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
	kind := report.CrashPanic
	if strings.HasPrefix(tail, "fatal error: ") {
		kind = report.CrashFatal
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
