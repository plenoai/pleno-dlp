package crash

import (
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Compare the detector pass with the pattern-only baseline at feedback sizes.
func BenchmarkFeedbackRedaction(b *testing.B) {
	registered := detectors.All()
	for _, input := range []struct {
		name string
		text string
	}{
		{"short", "The scanner reports a false positive in my application configuration."},
		{"limit", strings.Repeat("config: password = \"Tr0ub4dor&3xyz\" postgres user\n", 670)[:MaxReportBytes-1024]},
	} {
		for _, mode := range []struct {
			name string
			all  []detectors.Detector
		}{
			{"patterns", nil},
			{"all_detectors", registered},
		} {
			b.Run(input.name+"/"+mode.name, func(b *testing.B) {
				red := &Redactor{Detectors: mode.all}
				b.SetBytes(int64(len(input.text)))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_ = red.Redact(input.text)
				}
				b.ReportMetric(float64(len(mode.all)), "detectors")
			})
		}
	}
}
