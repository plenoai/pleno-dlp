package crash

import (
	"fmt"
	"runtime/debug"
)

// Recover preserves immediate redacted telemetry for main-goroutine panics,
// then re-panics so the runtime's crash writer records the fatal dump.
func (rt *Runtime) Recover(args []string, fn func() error) error {
	defer func() {
		v := recover()
		if v == nil {
			return
		}
		if rt.Getenv(EnvDisable) != "1" {
			rt.handle(KindRecovered, fmt.Sprintf("panic: %v", v), string(debug.Stack()), args)
		}
		panic(v)
	}()
	return fn()
}
