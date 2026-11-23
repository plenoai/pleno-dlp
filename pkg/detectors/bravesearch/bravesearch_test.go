//go:build detector_unit

package bravesearch

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "BSAR" + "GMxtVx9zvLTjuKrHK8yA94B8XXo"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"bsa placeholder", ""},
	})
}
