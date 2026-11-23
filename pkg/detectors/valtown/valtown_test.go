//go:build detector_unit

package valtown

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "vtwn" + "_eopr2P3t9pi2yoonP4JQmiDPUX4W32QC"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"vtwn_ placeholder", ""},
	})
}
