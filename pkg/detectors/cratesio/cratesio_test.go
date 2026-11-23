//go:build detector_unit

package cratesio

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "ciog" + "pUArLhnw2AX2577McKip3w6XQb3RAPz"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "CRATES_IO_TOKEN=" + want + "\n",
		Want:      want,
		Negatives: []string{"crates placeholder", ""},
	})
}
