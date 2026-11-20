//go:build js || wasip1

package crash

// StartMonitor is a no-op where the platform cannot re-exec.
func (rt *Runtime) StartMonitor(argv, env []string) (stop func(), err error) {
	return func() {}, ErrNotMonitored
}
