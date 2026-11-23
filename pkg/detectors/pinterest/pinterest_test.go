//go:build detector_unit

package pinterest

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "pina" + "_m8jR2AGUQW6DPSPNYUjJgbvNHUS3uyZFAGFkfKVu"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"pina_ placeholder", ""},
	})
}
