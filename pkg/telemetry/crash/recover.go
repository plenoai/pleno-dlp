package crash

import (
	"fmt"
	"runtime/debug"
)

// Recover runs fn and converts a main-goroutine panic into a spooled
// "recovered" report followed by Exit(2). Inside a supervised child it does
// nothing, so the runtime's own dump reaches the supervisor and the crash is
// reported exactly once.
func (rt *Runtime) Recover(args []string, fn func() error) (err error) {
	if rt.Getenv(EnvChild) != "" {
		return fn()
	}
	defer func() {
		v := recover()
		if v == nil {
			return
		}
		stack := string(debug.Stack())
		rt.handle(KindRecovered, fmt.Sprintf("panic: %v", v), stack, args)
		fmt.Fprintf(rt.Stderr, "panic: %v\n\n%s", v, stack)
		rt.Exit(2)
	}()
	return fn()
}
