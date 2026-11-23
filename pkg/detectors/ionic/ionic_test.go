//go:build detector_unit

package ionic

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "ion_" + "wePVS9gymQrYTsshigrqLAzzWqYCFsQ6pM9DWvKsNe"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"ion_ placeholder", ""},
	})
}
