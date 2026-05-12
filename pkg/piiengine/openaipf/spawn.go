package openaipf

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
// Standard "ask the kernel for a free port" trick. The TOCTOU between
// Close() and the child's Listen() is harmless: Supervisor.Start
// surfaces a lost race as ErrReadyTimeout via the /ready poll, which
// is the same failure path as any other startup error. Mirrors
// anonymize.pickPort exactly so behavior is identical regardless of
// engine choice.
func pickPort(host string) (int, error) {
	if host == "" {
		host = "127.0.0.1"
	}
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, fmt.Errorf("openaipf: reserve port: %w", err)
	}
	defer l.Close()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("openaipf: unexpected listen address type %T", l.Addr())
	}
	return addr.Port, nil
}

// substitutePort returns a copy of argv with every occurrence of the
// literal "{PORT}" replaced by the chosen port number. Substitution
// is per-token, not whole-string, because most argv entries are
// already split words: the supervisor doesn't parse a shell-quoted
// string.
//
// The CLI's documented default argv is
// `pleno-dlp openai-pf-server --port {PORT}` (ADR-0004); the {PORT}
// token is the only piece this function rewrites. Operators with
// custom argvs keep the same placeholder convention.
func substitutePort(argv []string, port int) []string {
	out := make([]string, len(argv))
	portStr := strconv.Itoa(port)
	for i, a := range argv {
		out[i] = strings.ReplaceAll(a, "{PORT}", portStr)
	}
	return out
}

// buildCmd assembles an *exec.Cmd from a port-substituted argv.
// Lives here (not inline in supervisor.go) so spawn-related behaviors
// — argv shape, env passthrough, eventual cgroup or process-group
// hooks — collect in one file.
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
		// reach here. Defensive nil-return signals an upstream bug
		// rather than dereferencing exec.Command on an empty name.
		return nil
	}
	return exec.Command(argv[0], argv[1:]...)
}
