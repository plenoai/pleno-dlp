// Regression checks for the perf rework — verify the optimisations
// don't hide credentials from detectors that legitimately span
// past the vicinity / window radius.
package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type collectSink struct {
	mu       sinkMutex
	findings []Finding
}

type sinkMutex struct{}

func (sinkMutex) Lock()   {}
func (sinkMutex) Unlock() {}

func (s *collectSink) Emit(f Finding)  { s.findings = append(s.findings, f) }
func (s *collectSink) Close() error    { return nil }

// constSource emits one chunk and closes.
type constSource struct{ data []byte }

func (constSource) Type() sources.SourceType { return sources.SourceUnknown }
func (constSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}
func (s constSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	ch <- &sources.Chunk{SourceType: sources.SourceUnknown, SourceName: "x", Data: s.data}
	return nil
}

// realRSA8192 is a real-world-shape PEM block: BEGIN/END headers ~5400
// bytes apart. The base64 body is opaque noise — the engine path
// doesn't need a parseable key, just byte distances. The PrivateKeyPEM
// detector's regex matches the BEGIN...END envelope; the deriveResult
// then tries to decode it. Even decoder failure is a Finding from the
// engine's perspective: the regex matched, so the detector emits.
func makeLargePEM(bodyBytes int) []byte {
	const unit = "MIIEowIBAAKCAQEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n"
	repeats := bodyBytes/len(unit) + 1
	body := strings.Repeat(unit, repeats)
	return []byte("-----BEGIN RSA PRIVATE KEY-----\n" + body + "-----END RSA PRIVATE KEY-----\n")
}

func TestRegression_LargePEMSpanningVicinity(t *testing.T) {
	// A 5.4 KiB PEM block. BEGIN/END "PRIVATE KEY" keywords are >4 KiB
	// apart, so a 2-KiB vicinity radius cannot cover the whole block
	// from either hit alone — only the union of both vicinities does.
	pem := makeLargePEM(5400)
	if len(pem) < 5400 {
		t.Fatalf("PEM too short: %d", len(pem))
	}

	sink := &collectSink{}
	eng := NewWithDetectors(detectors.All(), Options{Concurrency: 1}, sink)
	if err := eng.Run(context.Background(), constSource{data: pem}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got int
	for _, f := range sink.findings {
		if f.Detector == detectors.PrivateKeyPEM {
			got++
		}
	}
	if got == 0 {
		t.Errorf("PrivateKeyPEM not detected on 5.4 KiB PEM block — vicinity radius too small")
	}
}

func TestRegression_LargePEMBeyondVicinityUnion(t *testing.T) {
	// A 10 KiB PEM block — BEGIN/END keywords ~10 KiB apart. Even the
	// union of both 2-KiB vicinities leaves a ~5.9 KiB gap in the
	// middle. Because blockRe is `BEGIN...*?END`, both anchors must
	// fall in the same dispatched slice — if the dispatcher fragments
	// the block, the regex never sees both ends together and the
	// detector misses the key.
	pem := makeLargePEM(10000)
	sink := &collectSink{}
	eng := NewWithDetectors(detectors.All(), Options{Concurrency: 1}, sink)
	if err := eng.Run(context.Background(), constSource{data: pem}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got int
	for _, f := range sink.findings {
		if f.Detector == detectors.PrivateKeyPEM {
			got++
		}
	}
	if got == 0 {
		t.Errorf("PrivateKeyPEM not detected on 10 KiB PEM block — vicinity slice splits BEGIN/END apart")
	}
}

func TestRegression_PEMStraddlingWindowBoundary(t *testing.T) {
	// Push a 6 KiB PEM into the second window of a 40 KiB chunk so
	// part of it crosses the 32 KiB window boundary. With a 1 KiB
	// overlap, a 6 KiB PEM straddling the boundary is wider than the
	// overlap on either side, so neither window sees the full block.
	pem := makeLargePEM(6000)
	prefix := []byte(strings.Repeat("// padding\n", 2800)) // ~30 KiB of comments
	data := append(prefix, pem...)
	data = append(data, []byte(strings.Repeat("// tail\n", 200))...)

	sink := &collectSink{}
	eng := NewWithDetectors(detectors.All(), Options{Concurrency: 1}, sink)
	if err := eng.Run(context.Background(), constSource{data: data}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var got int
	for _, f := range sink.findings {
		if f.Detector == detectors.PrivateKeyPEM {
			got++
		}
	}
	if got == 0 {
		t.Errorf("PrivateKeyPEM not detected when PEM straddles 32 KiB window boundary")
	}
}
