//go:build detector_unit

package proof

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "prf_" + "rdZQLWuo6tzcgy96cAH2yeEX6e2GV7Ux"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"prf_ placeholder", ""},
	})
}
