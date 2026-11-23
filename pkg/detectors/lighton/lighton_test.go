//go:build detector_unit

package lighton

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "4NBU" + "yM7YZ9kV8KVJghhXE6M57suqSeXFbLg4WiSt6NdXQXNb"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "LIGHTON_API_KEY=" + want + "\n",
		Want:      want,
		Negatives: []string{"lighton placeholder", ""},
	})
}
