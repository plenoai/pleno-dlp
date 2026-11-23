//go:build detector_unit

package gcnotify

import (
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "ApiKey-v1 gcn" + "tfy-svc_jb14-" + strings.Join([]string{"879805fa", "e618", "bd1e", "f9d8", "0abfb58cfb06", "c0cdd43d", "c74c", "cc0a", "9e27", "de4e1520453a"}, "-")

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"gcntfy- placeholder", ""},
	})
}
