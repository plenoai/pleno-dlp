package all

import (
	"slices"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestProviderConfirmedDetectorSetIsExplicitlyAudited(t *testing.T) {
	var got []string
	for _, detector := range detectors.All() {
		policy, ok := detector.(detectors.VerificationPolicy)
		if !ok || policy.MaxVerificationAssurance() != detectors.AssuranceProviderConfirmed {
			continue
		}
		got = append(got, detector.Type().String())
	}
	slices.Sort(got)

	want := []string{"Apollo"}
	if !slices.Equal(got, want) {
		t.Fatalf("provider-confirmed detectors = %v, want explicitly audited set %v", got, want)
	}
}
