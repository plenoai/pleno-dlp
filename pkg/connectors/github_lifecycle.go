package connectors

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type githubUnitEmission struct {
	data []byte
	meta sources.Metadata
	ack  chan error
}
type githubOrderedEmitter struct {
	ctx        context.Context
	cancel     context.CancelFunc
	channels   []chan githubUnitEmission
	unitDone   []chan struct{}
	downstream Emit
	done       chan struct{}
	mu         sync.Mutex
	err        error
}

func newGitHubOrderedEmitter(ctx context.Context, n int, downstream Emit) *githubOrderedEmitter {
	runCtx, cancel := context.WithCancel(ctx)
	o := &githubOrderedEmitter{ctx: runCtx, cancel: cancel, channels: make([]chan githubUnitEmission, n), unitDone: make([]chan struct{}, n), downstream: downstream, done: make(chan struct{})}
	for i := range o.channels {
		o.channels[i] = make(chan githubUnitEmission, 1)
		o.unitDone[i] = make(chan struct{})
	}
	go func() {
		defer close(o.done)
		for i, ch := range o.channels {
			for {
				select {
				case item, ok := <-ch:
					if !ok {
						close(o.unitDone[i])
						goto next
					}
					o.mu.Lock()
					failed := o.err != nil
					o.mu.Unlock()
					if failed {
						item.ack <- o.error()
						continue
					}
					if err := o.downstream(item.data, item.meta); err != nil {
						o.mu.Lock()
						if o.err == nil {
							o.err = err
						}
						o.mu.Unlock()
						item.ack <- err
						cancel()
						return
					}
					item.ack <- nil
				case <-o.ctx.Done():
					return
				}
			}
		next:
		}
	}()
	return o
}
func (o *githubOrderedEmitter) Emit(index int) Emit {
	return func(data []byte, meta sources.Metadata) error {
		item := githubUnitEmission{data: data, meta: meta, ack: make(chan error, 1)}
		select {
		case o.channels[index] <- item:
		case <-o.ctx.Done():
			return o.error()
		}
		select {
		case err := <-item.ack:
			return err
		case <-o.ctx.Done():
			return o.error()
		}
	}
}
func (o *githubOrderedEmitter) Close(index int) error {
	close(o.channels[index])
	select {
	case <-o.unitDone[index]:
		return o.error()
	case <-o.ctx.Done():
		return o.error()
	}
}
func (o *githubOrderedEmitter) error() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.err != nil {
		return o.err
	}
	return o.ctx.Err()
}
func (o *githubOrderedEmitter) Wait() error { <-o.done; return o.error() }

const (
	githubDefaultRepoConcurrency = 1
	githubMaxRepoConcurrency     = 32
)

// githubSourceUnit is the common scheduling identity for every independently
// resumable GitHub scan surface. Surface and ID form the incremental-state
// namespace; producers may attach metadata and a resource budget without
// changing the lifecycle.
type githubSourceUnit struct {
	Surface  string
	ID       string
	Metadata map[string]string
	Budget   githubUnitBudget
}

type githubUnitBudget struct {
	MaxBytes int64
	MaxItems int64
}

func (u githubSourceUnit) Key() string { return u.Surface + ":" + u.ID }

type githubUnitStats struct {
	CostBytes int64
	CostItems int64
	Skipped   string
}

type githubUnitResult[T any] struct {
	Unit  githubSourceUnit
	State T
	Stats githubUnitStats
	Err   error
}

type githubLifecycleStats struct {
	Total        int
	Completed    int
	Failed       int
	Skipped      map[string]int
	CostBytes    int64
	CostItems    int64
	PeakInFlight int
}

func githubRepoConcurrency(cfg Config) (int, error) {
	raw := cfg.Get("repo_concurrency", strconv.Itoa(githubDefaultRepoConcurrency))
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > githubMaxRepoConcurrency {
		return 0, fmt.Errorf("github: repo_concurrency must be between 1 and %d, got %q", githubMaxRepoConcurrency, raw)
	}
	return n, nil
}

// runGitHubSourceUnits executes producers concurrently but commits their
// results in input order. Ordered commit makes partial state byte-for-byte
// deterministic across completion schedules and guarantees a resume never
// persists a later unit while an earlier unit is still unresolved.
//
// Unit failures are isolated. Cancellation and deadlines remain source-wide
// failures and stop scheduling promptly.
func runGitHubSourceUnits[T any](
	ctx context.Context,
	units []githubSourceUnit,
	concurrency int,
	produce func(context.Context, githubSourceUnit) githubUnitResult[T],
	commit func(int, githubUnitResult[T]) error,
) (githubLifecycleStats, error) {
	stats := githubLifecycleStats{Total: len(units), Skipped: map[string]int{}}
	if len(units) == 0 {
		return stats, nil
	}
	if concurrency < 1 {
		return stats, errors.New("github: source-unit concurrency must be positive")
	}
	if concurrency > len(units) {
		concurrency = len(units)
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type indexedResult struct {
		index  int
		result githubUnitResult[T]
	}
	results := make(chan indexedResult, concurrency)
	launch := func(index int) {
		go func() {
			result := produce(runCtx, units[index])
			result.Unit = units[index]
			select {
			case results <- indexedResult{index: index, result: result}:
			case <-runCtx.Done():
			}
		}()
	}

	pending := make(map[int]githubUnitResult[T], concurrency)
	next := 0
	launched := 0
	for launched < concurrency {
		launch(launched)
		launched++
	}
	for next < len(units) {
		var item indexedResult
		select {
		case item = <-results:
		case <-ctx.Done():
			return stats, ctx.Err()
		}
		pending[item.index] = item.result
		if len(pending) > stats.PeakInFlight {
			stats.PeakInFlight = len(pending)
		}
		for {
			result, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			if err := commit(next, result); err != nil {
				cancel()
				return stats, err
			}
			stats.CostBytes += result.Stats.CostBytes
			stats.CostItems += result.Stats.CostItems
			if result.Stats.Skipped != "" {
				stats.Skipped[result.Stats.Skipped]++
			}
			if result.Err != nil {
				stats.Failed++
			} else {
				stats.Completed++
			}
			next++
		}
		// Keep at most one concurrency-wide identity window scheduled beyond
		// the next uncommitted unit. If the first unit stalls, later outcomes
		// cannot accumulate in proportion to the organisation size.
		for launched < len(units) && launched-next < concurrency {
			launch(launched)
			launched++
		}
	}
	if err := ctx.Err(); err != nil {
		return stats, err
	}
	return stats, nil
}
