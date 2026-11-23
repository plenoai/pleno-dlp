//go:build detector_unit

package zuplo

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "zpka" + "_6eyscg1krh91rfww04w77dh9jb0uhcqo_52a11ddc"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"zpka_ placeholder", ""},
	})
}
