//go:build detector_unit

package bitly

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "6d14" + "3d924134a90e61b09ecd0dc2a0ba5b22d706"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "BITLY_ACCESS_TOKEN=" + want + "\n",
		Want:      want,
		Negatives: []string{"bitly placeholder", ""},
	})
}
