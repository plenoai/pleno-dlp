//go:build detector_unit

package llamacloud

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "llx-" + "qL2APV7vAa26nSx47omxVNWHAQLgcKFZ6UHuS98aJaeEcg7C"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"llx- placeholder", ""},
	})
}
