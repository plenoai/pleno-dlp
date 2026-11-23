//go:build detector_unit

package nuget

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "oy2a" + "eef7g2qezm4h3x5ajlpc3eaohkakh73ven2ue6347e"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"oy2 placeholder", ""},
	})
}
