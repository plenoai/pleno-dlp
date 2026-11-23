//go:build detector_unit

package sourcegraph

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "sgp_" + "438ea0c1b7a83b73_5ca2dfaa881d833609c793974d394f75286fc4b9"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"sgp_ placeholder", ""},
	})
}
