//go:build detector_unit

package frameio

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "fio-" + "u-2obfUqWQKJB8GecrLhiedJqBKFoiNsWbcRGg4Y7QL7QMAbvZBCRN9mZkx4xhC8t9"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"fio-u- placeholder", ""},
	})
}
