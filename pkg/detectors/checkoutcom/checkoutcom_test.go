//go:build detector_unit

package checkoutcom

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "sk_f" + "ef7e249-b078-d7a2-afc4-87a69311d21f"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "CHECKOUT_SECRET_KEY=" + want + "\n",
		Want:      want,
		Negatives: []string{"checkout placeholder", ""},
	})
}
