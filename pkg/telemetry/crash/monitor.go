package crash

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime/debug"
)

// MonitorMarker is the EnvChild value that tells the re-executed binary to
// run as a crash monitor instead of the CLI.
const MonitorMarker = "monitor"

// IsMonitor reports whether this process was started by StartMonitor.
func (rt *Runtime) IsMonitor() bool { return rt.Getenv(EnvChild) == MonitorMarker }

// StartMonitor re-executes the binary as a crash monitor when crash reports
// are enabled and points debug.SetCrashOutput at a private pipe to it, so a
// fatal runtime error in this process reaches the monitor's handle path.
// The CLI keeps running in-process. When disabled, or when this process is
// itself a child or monitor, it returns ErrNotSupervised without starting
// anything.
func (rt *Runtime) StartMonitor(argv, env []string) error {
	if rt.Getenv(EnvChild) != "" {
		return ErrNotSupervised
	}
	cfg, err := Load(rt.Getenv)
	if err != nil || !cfg.Enabled {
		return ErrNotSupervised
	}
	exe, err := rt.Executable()
	if err != nil {
		return errors.Join(ErrReexecFailed, err)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return errors.Join(ErrReexecFailed, err)
	}
	defer pr.Close()
	defer pw.Close()
	mon := exec.Command(exe, argv[1:]...)
	mon.Args[0] = argv[0]
	mon.Env = append(append([]string{}, env...), EnvChild+"="+MonitorMarker)
	mon.Stdin, mon.Stderr = pr, rt.Stderr
	if err := mon.Start(); err != nil {
		return errors.Join(ErrReexecFailed, err)
	}
	// SetCrashOutput duplicates the descriptor, so closing pw is safe; the
	// monitor sees EOF only when this process exits.
	if err := debug.SetCrashOutput(pw, debug.CrashOptions{}); err != nil {
		_ = mon.Process.Kill()
		_ = mon.Wait()
		return errors.Join(ErrReexecFailed, err)
	}
	go func() { _ = mon.Wait() }()
	return nil
}

// Monitor reads a crash dump from r until EOF, retaining at most ringSize
// bytes (pinned at the crash header), and reports it through handle. It
// returns false when the stream held no crash, e.g. on a clean exit.
func (rt *Runtime) Monitor(r io.Reader, args []string) (Outcome, bool) {
	ring := &ringBuffer{max: ringSize}
	_, _ = io.Copy(ring, r)
	kind, msg, stack, ok := parseCrash(ring.Crash())
	if !ok {
		return Outcome{}, false
	}
	return rt.handle(kind, msg, stack, args), true
}
