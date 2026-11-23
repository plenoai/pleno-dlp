//go:build detector_unit

package cursor

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "key_" + "e985d3640dc4b94c1370201016990c9a6aca30d054430e8c5dd5d5539350861b"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "CURSOR_API_KEY=" + want + "\n",
		Want:      want,
		Negatives: []string{"cursor placeholder", ""},
	})
}
