//go:build detector_unit

package falai

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "7d12" + "0f95-7582-69f6-8b1c-af5a08094c8c:b25da6d665feecd4daefe0f36a16d416"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "FAL_KEY=" + want + "\n",
		Want:      want,
		Negatives: []string{"fal_key placeholder", ""},
	})
}
