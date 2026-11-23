//go:build detector_unit

package instantly

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "qRf4" + "XSEySojJYqeCxeyuYfqnuoxiKabNDLadJa8CSmbJLhZ7F47wMuaCKN9pJ9tbHK=="

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "INSTANTLY_API_KEY=" + want + "\n",
		Want:      want,
		Negatives: []string{"instantly placeholder", ""},
	})
}
