//go:build detector_unit

package upstage

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "3mWo" + "39v5uLD2j99gFTbiCxHeVSvT3j334D9mdsvr6sYy"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "UPSTAGE_API_KEY=" + want + "\n",
		Want:      want,
		Negatives: []string{"upstage placeholder", ""},
	})
}
