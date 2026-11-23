//go:build detector_unit

package samsara

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "sams" + "ara_api_c8TModP9UXdWBPMxsBABeGmsNQYSNH"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"samsara_api_ placeholder", ""},
	})
}
