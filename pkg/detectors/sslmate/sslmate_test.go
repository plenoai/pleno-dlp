//go:build detector_unit

package sslmate

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "fzy6" + "4wAD2dPQLY59jPSkT5tqAM75m9MUgop4"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "SSLMATE_API_KEY=" + want + "\n",
		Want:      want,
		Negatives: []string{"sslmate placeholder", ""},
	})
}
