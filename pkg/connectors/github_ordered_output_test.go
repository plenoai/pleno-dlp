package connectors

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/output"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestGitHubOrderedEmitterSinkFailurePreventsCheckpointAndResumes(t *testing.T) {
	sinkErr := errors.New("sink failed on item 2")
	checkpoint := 0
	run := func(fail bool) error {
		o := newGitHubOrderedEmitter(context.Background(), 1, func(data []byte, _ sources.Metadata) error {
			if fail && string(data) == "item-2" {
				return sinkErr
			}
			return nil
		})
		emit := o.Emit(0)
		for _, item := range []string{"item-1", "item-2", "item-3"} {
			if err := emit([]byte(item), sources.Metadata{}); err != nil {
				_ = o.Close(0)
				return err
			}
		}
		if err := o.Close(0); err != nil {
			return err
		}
		checkpoint = 3
		return o.Wait()
	}
	if err := run(true); !errors.Is(err, sinkErr) {
		t.Fatalf("first run err=%v", err)
	}
	if checkpoint != 0 {
		t.Fatalf("checkpoint advanced after sink failure: %d", checkpoint)
	}
	if err := run(false); err != nil || checkpoint != 3 {
		t.Fatalf("resume err=%v checkpoint=%d", err, checkpoint)
	}
}

func TestGitHubOrderedEmitterCallerCancellationPreservesSinkError(t *testing.T) {
	sinkErr := errors.New("sink failed")
	for _, phase := range []string{"enqueue", "acknowledge", "wait-turn"} {
		for _, failed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/sink-failed=%t", phase, failed), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				// Hold the state between recording a sink failure and canceling
				// the emitter, so only the caller's cancellation branch is ready.
				o := &githubOrderedEmitter{
					ctx:       context.Background(),
					channels:  []chan githubUnitEmission{make(chan githubUnitEmission)},
					unitReady: []chan struct{}{make(chan struct{})},
				}
				want := context.Canceled
				if failed {
					o.err = sinkErr
					want = sinkErr
				}
				if phase == "acknowledge" {
					go func() {
						<-o.channels[0]
						cancel()
					}()
				} else {
					cancel()
				}
				var err error
				if phase == "wait-turn" {
					err = o.WaitTurn(ctx, 0)
				} else {
					err = o.EmitContext(ctx, 0)(nil, sources.Metadata{})
				}
				if !errors.Is(err, want) {
					t.Fatalf("error = %v, want %v", err, want)
				}
			})
		}
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	o := &githubOrderedEmitter{ctx: context.Background(), channels: []chan githubUnitEmission{nil}, unitReady: []chan struct{}{nil}}
	if err := o.EmitContext(ctx, 0)(nil, sources.Metadata{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("emit error = %v, want deadline exceeded", err)
	}
	if err := o.WaitTurn(ctx, 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait error = %v, want deadline exceeded", err)
	}
}

func renderOrderedGitHubOutput(t *testing.T, format string) []byte {
	t.Helper()
	var chunks []*sources.Chunk
	var mu sync.Mutex
	o := newGitHubOrderedEmitter(context.Background(), 3, func(data []byte, meta sources.Metadata) error {
		mu.Lock()
		defer mu.Unlock()
		chunks = append(chunks, &sources.Chunk{SourceType: sources.SourceGitHub, Data: append([]byte(nil), data...), SourceMetadata: meta})
		return nil
	})
	var wg sync.WaitGroup
	for _, i := range []int{2, 0, 1} {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			emit := o.Emit(i)
			_ = emit([]byte(fmt.Sprintf("secret-%d", i)), sources.Metadata{GitHub: &sources.GitHubMeta{Repository: fmt.Sprintf("acme/r%d", i), File: fmt.Sprintf("f%d", i)}})
			o.Close(i)
		}(i)
	}
	wg.Wait()
	if err := o.Wait(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	s, err := output.NewSink(format, &buf, "test")
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range chunks {
		s.Emit(engine.Finding{Detector: detectors.GenericHighEntropy, Chunk: c, Result: detectors.Result{Raw: []byte(fmt.Sprintf("secret-%d", i)), Redacted: fmt.Sprintf("s%d***", i), Severity: detectors.SeverityHigh}})
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestGitHubOrderedEmitterProducesByteIdenticalJSONAndSARIF(t *testing.T) {
	for _, format := range []string{"json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			want := renderOrderedGitHubOutput(t, format)
			for i := 0; i < 10; i++ {
				if got := renderOrderedGitHubOutput(t, format); !bytes.Equal(got, want) {
					t.Fatalf("iteration %d differs\nwant=%s\ngot=%s", i, want, got)
				}
			}
		})
	}
}
