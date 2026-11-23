//go:build detector_unit

package xendit

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "xnd_" + "production_9Hna5HJkagp4fdRjitjYQcLcLuFYLG3Q8KkKD6i7sSJUYcus3jzcx92MgHhW"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"xnd_production_ placeholder", ""},
	})
}
