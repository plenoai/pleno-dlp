//go:build !js && !wasip1

package crash

import (
	"errors"
	"os"
	"os/exec"
	"runtime/debug"
)

// StartMonitor re-executes the binary as a crash monitor when crash reports
// are enabled and points debug.SetCrashOutput at a private pipe to its
// stdin. The returned stop func detaches crash output and waits for the
// monitor, which exits on EOF. When disabled, or in a child or monitor
// process, it returns ErrNotMonitored without starting anything.
func (rt *Runtime) StartMonitor(argv, env []string) (stop func(), err error) {
	if rt.Getenv(EnvChild) != "" {
		return func() {}, ErrNotMonitored
	}
	cfg, err := Load(rt.Getenv)
	if err != nil || !cfg.Enabled {
		return func() {}, ErrNotMonitored
	}
	exe, err := rt.Executable()
	if err != nil {
		return func() {}, errors.Join(ErrReexecFailed, err)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return func() {}, errors.Join(ErrReexecFailed, err)
	}
	mon := exec.Command(exe, argv[1:]...)
	mon.Args[0] = argv[0]
	mon.Env = append(append([]string{}, env...), EnvChild+"="+MonitorMarker)
	mon.Stdin, mon.Stderr = pr, rt.Stderr
	if err := mon.Start(); err != nil {
		pr.Close()
		pw.Close()
		return func() {}, errors.Join(ErrReexecFailed, err)
	}
	pr.Close()
	// SetCrashOutput duplicates the descriptor, so ours can be closed.
	err = debug.SetCrashOutput(pw, debug.CrashOptions{})
	pw.Close()
	if err != nil {
		_ = mon.Wait()
		return func() {}, errors.Join(ErrReexecFailed, err)
	}
	return func() {
		_ = debug.SetCrashOutput(nil, debug.CrashOptions{})
		_ = mon.Wait()
	}, nil
}
