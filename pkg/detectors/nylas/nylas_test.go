//go:build detector_unit

package nylas

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "nyk_" + "2HPqQkrDhkgtfnXe7P74sX5xdfy6nbPGmSMzJrXpiFZ3NFWNZBJoHpytzb6YmTvVTYT"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"nyk_ placeholder", ""},
	})
}
