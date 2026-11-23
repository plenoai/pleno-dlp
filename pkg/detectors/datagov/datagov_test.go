//go:build detector_unit

package datagov

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "APgk" + "y2sNY5s9SrFBjuSbDzADLzFwBphFygoEFSLN"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "data.gov_api_key=" + want + "\n",
		Want:      want,
		Negatives: []string{"data.gov placeholder", ""},
	})
}
