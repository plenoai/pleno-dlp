//go:build detector_unit

package disqus

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "UV5h" + "KTHrHCyzezJMMaXTMa9NwCdzac7J5pFtG4LiWCwaxCC6tpcSWB9et4CCdNYa"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "DISQUS_API_SECRET=" + want + "\n",
		Want:      want,
		Negatives: []string{"disqus placeholder", ""},
	})
}
