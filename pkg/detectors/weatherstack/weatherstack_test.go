//go:build detector_unit

package weatherstack

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "0r7s" + "k7was9f4kghnv7ssyx9jsit35xz8"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "WEATHERSTACK_API_KEY=" + want + "\n",
		Want:      want,
		Negatives: []string{"weatherstack placeholder", ""},
	})
}
