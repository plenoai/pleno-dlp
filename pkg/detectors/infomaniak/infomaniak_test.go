//go:build detector_unit

package infomaniak

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "GRFy" + "AsQSfbUYWS5EiRYKe2jYkFiUKSGTQbYbe6iNKoTm9GQmwXF3gpEiew7dgAXkm9pASgXA"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "INFOMANIAK_TOKEN=" + want + "\n",
		Want:      want,
		Negatives: []string{"infomaniak placeholder", ""},
	})
}
