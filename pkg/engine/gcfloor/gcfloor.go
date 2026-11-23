// Package gcfloor gives the Go heap goal a floor: the collector's next goal
// is max(Floor, the GOGC=100 goal). A scan allocates its working set in
// the first fraction of a second, and from the runtime's 4 MiB starting
// goal the default pacing ran a dozen collections on the way up (about 8%
// of a small repository's history-scan CPU, #1046). Above the floor the
// pacing is the default one, so large scans keep their peak heap.
package gcfloor

import (
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"sync"
)

// Floor is the heap goal below which no collection is triggered.
const Floor = 256 << 20

// maxPercent bounds the GOGC value used while the live heap is tiny.
const maxPercent = 1 << 14

var once sync.Once

// Enable installs the floor unless the user set GOGC or GOMEMLIMIT, whose
// explicit pacing always wins. It is idempotent.
func Enable() {
	if os.Getenv("GOGC") != "" || os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	once.Do(func() {
		adjust()
		arm()
	})
}

// Percent returns the GOGC value that makes the goal max(Floor, 2*live).
func Percent(live uint64) int {
	if live == 0 || live*2 >= Floor {
		return 100
	}
	p := int(Floor/live)*100 - 100
	return min(max(p, 100), maxPercent)
}

var liveSample = []metrics.Sample{{Name: "/gc/heap/live:bytes"}}

func adjust() {
	metrics.Read(liveSample)
	live := uint64(0)
	if liveSample[0].Value.Kind() == metrics.KindUint64 {
		live = liveSample[0].Value.Uint64()
	}
	if live == 0 {
		// Before the first collection: the goal starts from the 4 MiB
		// minimum heap.
		live = 4 << 20
	}
	debug.SetGCPercent(Percent(live))
}

// sentinel is large enough to stay out of the tiny allocator, whose
// blocks would delay the cleanup past the cycle that freed it.
type sentinel struct{ _ [16]byte }

// arm re-runs adjust after the next collection: the cleanup of an
// unreachable sentinel runs once that cycle has finished.
func arm() {
	s := new(sentinel)
	runtime.AddCleanup(s, func(struct{}) {
		adjust()
		arm()
	}, struct{}{})
}
