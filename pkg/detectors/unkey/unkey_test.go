//go:build detector_unit

package unkey

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "unke" + "y_ZK3PW3bjFFTmaoVSSqe6rkHhmDPu"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"unkey_ placeholder", ""},
	})
}
