//go:build detector_unit

package apify

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "apif" + "y_api_zTq9XeDEApzmhrLVp5pRKFwJ9MARqzQWuz9g"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"apify_api_ placeholder", ""},
	})
}
