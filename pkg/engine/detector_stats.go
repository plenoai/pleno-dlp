package engine

import (
	"sort"
	"sync/atomic"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// DetectorStat is one detector's activity during a run (--rule-stats).
// Calls counts detector passes (keyword-gated FromData invocations),
// Results counts candidates returned before dedup/allowlist, and Duration
// is the summed wall time including verification.
type DetectorStat struct {
	Detector detectors.DetectorType `json:"detector"`
	Calls    int64                  `json:"calls"`
	Results  int64                  `json:"results"`
	Duration time.Duration          `json:"duration"`
}

type detectorStatCounters struct {
	calls, results, nanos atomic.Int64
}

func newDetectorStatCounters(enabled bool, n int) []detectorStatCounters {
	if !enabled {
		return nil
	}
	return make([]detectorStatCounters, n)
}

func (c *detectorStatCounters) record(d time.Duration, results int) {
	c.calls.Add(1)
	c.results.Add(int64(results))
	c.nanos.Add(int64(d))
}

// DetectorStats returns per-detector activity for detectors that ran at
// least once, slowest first. It is nil unless Options.DetectorStats is set.
func (e *Engine) DetectorStats() []DetectorStat {
	if e.detStats == nil {
		return nil
	}
	var out []DetectorStat
	for i := range e.detStats {
		c := &e.detStats[i]
		if calls := c.calls.Load(); calls > 0 {
			out = append(out, DetectorStat{Detector: e.dets[i].Type(), Calls: calls, Results: c.results.Load(), Duration: time.Duration(c.nanos.Load())})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Duration != out[j].Duration {
			return out[i].Duration > out[j].Duration
		}
		return out[i].Detector.String() < out[j].Detector.String()
	})
	return out
}
