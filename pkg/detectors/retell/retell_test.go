//go:build detector_unit

package retell

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "key_" + "a747d388e800843bc86b2b6956f1"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "RETELL_API_KEY=" + want + "\n",
		Want:      want,
		Negatives: []string{"retell placeholder", ""},
	})
}
