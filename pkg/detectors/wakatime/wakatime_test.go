//go:build detector_unit

package wakatime

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "waka" + "_6it84q4e8kxo1g7bysftdxik9uwepbpwv9aom8td"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"waka placeholder", ""},
	})
}
