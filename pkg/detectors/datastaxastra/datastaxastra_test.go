//go:build detector_unit

package datastaxastra

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "Astr" + "aCS:kyr8jPUiekG4v35YMPrmHsa7:f759b118fc04168aa79d77775efd399cea008d65e5558d888d6a3fed51bbc885"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"astracs: placeholder", ""},
	})
}
