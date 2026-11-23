//go:build detector_unit

package mergify

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "merg" + "ify_application_key_wQWjkAedD549zzmy4DzZSPXZGCmtZMjVfu6bwL2WTUQNE8L7"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"mergify_application_key_ placeholder", ""},
	})
}
