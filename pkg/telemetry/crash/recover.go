package crash

import (
	"fmt"
	"runtime/debug"
)

// Recover runs fn and converts a main-goroutine panic into a spooled
// "recovered" report followed by Exit(2). The crash monitor only sees
// unrecovered crashes, so each crash is reported exactly once.
func (rt *Runtime) Recover(args []string, fn func() error) (err error) {
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
