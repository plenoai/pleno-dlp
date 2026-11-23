//go:build detector_unit

package databento

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "db-x" + "7c79Fijk4VKzdeo6synHQvke56Q5"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "DATABENTO_API_KEY=" + want + "\n",
		Want:      want,
		Negatives: []string{"databento placeholder", ""},
	})
}
