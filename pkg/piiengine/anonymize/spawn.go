package anonymize

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

// pickPort reserves an ephemeral loopback port. The returned listener
// is closed before the function returns; the caller exec's the child
// process bound to the same port number.
//
// This is the standard "ask the kernel for a free port" trick. There
// is a tiny TOCTOU race between Close() and the child's Listen(), but
// for a single-developer scan started from a CLI it's good enough —
// and Supervisor.Start treats a failed /ready poll as a startup
// failure regardless of root cause, so a lost port race surfaces as
// a clean ErrReadyTimeout rather than a silent hang.
func pickPort(host string) (int, error) {
	if host == "" {
		host = "127.0.0.1"
	}
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, fmt.Errorf("anonymize: reserve port: %w", err)
	}
	defer l.Close()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("anonymize: unexpected listen address type %T", l.Addr())
	}
	return addr.Port, nil
}

// substitutePort returns a copy of argv with every occurrence of the
// literal "{PORT}" replaced by the chosen port number. Substitution
// is per-token, not whole-string, because most argv entries are
// already split words: the supervisor doesn't try to parse a shell
// quoted string.
func substitutePort(argv []string, port int) []string {
	out := make([]string, len(argv))
	portStr := strconv.Itoa(port)
	for i, a := range argv {
		out[i] = strings.ReplaceAll(a, "{PORT}", portStr)
	}
	return out
}

// buildCmd assembles an *exec.Cmd from a port-substituted argv.
// Lives here (not inline in supervisor.go) so spawn-related
// behaviors — argv shape, env passthrough, eventual cgroup or
// process-group hooks — collect in one file.
//
// We deliberately do NOT call cmd.SysProcAttr.Setpgid: on Unix that
// would isolate the child from terminal signals, but we want SIGINT
// at the controlling terminal to reach both the parent (cleanly
// cancelling the scan context) and any descendant Python processes
// the child may have forked. Stop() handles graceful shutdown
// regardless.
func buildCmd(argv []string) *exec.Cmd {
	if len(argv) == 0 {
		// Caller-side guarantee: New() rejects empty Cmd before we
		// reach here. Defensive panic-equivalent: an exec.Command
		// with empty name would dereference invalid memory in
		// older Go; explicitly nil-return signals the bug.
		return nil
	}
	return exec.Command(argv[0], argv[1:]...)
}
