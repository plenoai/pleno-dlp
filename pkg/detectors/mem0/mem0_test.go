//go:build detector_unit

package mem0

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "m0-m" + "JshWV6UrvvyX5WZ5c4qdiu3UtdfzwRBh5fhXSMA"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "MEM0_API_KEY=" + want + "\n",
		Want:      want,
		Negatives: []string{"mem0 placeholder", ""},
	})
}
