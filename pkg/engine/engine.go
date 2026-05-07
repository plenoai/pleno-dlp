// Package engine drives the scan loop: it pulls chunks from a Source, runs
// each registered Detector against chunks whose data contains at least one of
// the detector's keywords, and forwards results to the configured output sink.
//
// This file contains only the skeleton; concrete chunking, dedup, and filter
// behavior lives in dedup.go / filter.go and is filled in by core-engineer.
package engine

import (
	"bytes"
	"context"
	"strings"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/decoder"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type Finding struct {
	Result   detectors.Result
	Chunk    *sources.Chunk
	Detector detectors.DetectorType
}

type Sink interface {
	Emit(Finding)
	Close() error
}

type Options struct {
	Verify      bool
	Concurrency int
}

type Engine struct {
	opts Options
	dets []detectors.Detector
	sink Sink
}

func New(opts Options, sink Sink) *Engine {
	return NewWithDetectors(detectors.All(), opts, sink)
}

// NewWithDetectors builds an engine with an explicit detector list. The CLI
// uses this to compose registered built-ins with custom rules loaded from
// disk; tests use it to inject pinpoint detectors. Concurrency is clamped
// here so callers don't need to remember the floor.
func NewWithDetectors(dets []detectors.Detector, opts Options, sink Sink) *Engine {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	return &Engine{opts: opts, dets: dets, sink: sink}
}

// Run streams chunks from src and dispatches them across worker goroutines.
// Returns when src.Chunks returns or ctx is cancelled.
func (e *Engine) Run(ctx context.Context, src sources.Source) error {
	ch := make(chan *sources.Chunk, e.opts.Concurrency*2)

	var wg sync.WaitGroup
	for i := 0; i < e.opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range ch {
				e.scanChunk(ctx, c)
			}
		}()
	}

	srcErr := src.Chunks(ctx, ch)
	close(ch)
	wg.Wait()
	return srcErr
}

func (e *Engine) scanChunk(ctx context.Context, c *sources.Chunk) {
	// Variants[0] is always c.Data unchanged (Source=""). Subsequent
	// entries are base64/percent/hex decode results, included only when
	// the chunk contained candidate runs. The cost is one regex sweep
	// per chunk on the cold path — paid once whether or not any detector
	// runs — and amortises against the keyword-matching that follows.
	variants := decoder.Variants(c.Data)

	for _, d := range e.dets {
		kws := d.Keywords()
		for _, v := range variants {
			if !keywordMatch(v.Data, kws) {
				continue
			}
			results, err := d.FromData(ctx, e.opts.Verify, v.Data)
			if err != nil {
				continue
			}
			for _, r := range results {
				if v.Source != "" {
					// Mark which decode produced the hit so output
					// can disambiguate "found in base64-encoded
					// payload" from "found in plain text".
					if r.ExtraData == nil {
						r.ExtraData = map[string]string{}
					}
					r.ExtraData["decoded_from"] = v.Source
				}
				// Detectors may set Severity directly; when zero
				// (the default), derive one so every finding is
				// triageable downstream.
				if r.Severity == detectors.SeverityUnknown {
					r.Severity = detectors.DefaultSeverity(d.Type(), r.Verified)
				}
				e.sink.Emit(Finding{Result: r, Chunk: c, Detector: d.Type()})
			}
		}
	}
}

// keywordMatch returns true when data contains any keyword (case-insensitive).
// Empty keyword list always returns false — a detector with no keywords is a
// configuration mistake, not an opt-in to scan everything.
func keywordMatch(data []byte, kws []string) bool {
	if len(kws) == 0 {
		return false
	}
	lower := bytes.ToLower(data)
	for _, kw := range kws {
		if bytes.Contains(lower, []byte(strings.ToLower(kw))) {
			return true
		}
	}
	return false
}
