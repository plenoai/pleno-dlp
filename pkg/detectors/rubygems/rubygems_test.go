//go:build detector_unit

package rubygems

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "ruby" + "gems_487b0ea58ce5e2dabebc1d0a7eb98e008dc0be3b1133e9cd"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"rubygems_ placeholder", ""},
	})
}
