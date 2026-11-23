//go:build detector_unit

package polar

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "pola" + "r_pat_XmwvpADxq6fv5ifEWYiKjEcWfiSbQdqttrwzHBSJ"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"polar_at_ placeholder", ""},
	})
}
