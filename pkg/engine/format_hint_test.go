package engine

import (
	"context"
	"math/rand"
	"slices"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const formatHintProbeType = detectors.DetectorType(1<<29 + 1046)

type formatHintProbe struct{}

func (formatHintProbe) Type() detectors.DetectorType { return formatHintProbeType }
func (formatHintProbe) Keywords() []string           { return []string{"nativekw"} }
func (formatHintProbe) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return nil, nil
}

func scanRaws(t *testing.T, data []byte, noHint bool) []string {
	t.Helper()
	collector := &resultCollector{}
	eng := NewWithDetectors([]detectors.Detector{formatHintProbe{}}, Options{NoVerify: true}, collector)
	eng.noFormatHint = noHint
	src := &bytesSource{chunk: &sources.Chunk{SourceType: sources.SourceUnknown, SourceName: "hint", Data: data}}
	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range collector.snapshot() {
		out = append(out, string(r.Raw))
	}
	slices.Sort(out)
	return out
}

// TestFormatKeywordHintMatchesSearch pins the dispatch hint (#1046): a
// window whose span merged no format-keyword hit skips the ASCII format
// keyword search, and findings stay those of searching every window,
// including near the runes Unicode lowering maps into ASCII.
func TestFormatKeywordHintMatchesSearch(t *testing.T) {
	detectors.RegisterFormats(formatHintProbeType,
		&detectors.Format{ID: "test.hint-ascii", Keywords: []string{"probe_"}, Pattern: `probe_[a-z0-9]{12}`},
		&detectors.Format{ID: "test.hint-k", Keywords: []string{"kq_"}, Pattern: `(?i)[k\x{212a}]q_([a-z0-9]{12})`, Group: 1},
		&detectors.Format{ID: "test.hint-uni", Keywords: []string{"ǆq_"}, Pattern: `(?i)ǆq_([a-z0-9]{12})`, Group: 1},
	)
	parts := []string{"nativekw ", "probe_", "PROBE_", "kq_", "KQ_", "Kq_", "İ", "ǆq_", "Ǆq_",
		"a1b2c3d4e5f6", "zz9yy8xx7ww6", " ", "\n", strings.Repeat("x", 300), "=", "q_"}
	r := rand.New(rand.NewSource(1046))
	for i := range 3000 {
		var b strings.Builder
		for range r.Intn(40) {
			b.WriteString(parts[r.Intn(len(parts))])
		}
		data := []byte(b.String())
		got, want := scanRaws(t, data, false), scanRaws(t, data, true)
		if !slices.Equal(got, want) {
			t.Fatalf("case %d %q: got %q, want %q", i, data, got, want)
		}
	}
}
