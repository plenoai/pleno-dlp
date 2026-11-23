//go:build detector_unit

package labelbox

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "lbx_" + "khQEPagsZhSk42963vaGM56byAHUFD2H3V7rDow5YkQ"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"lbx_ placeholder", ""},
	})
}
