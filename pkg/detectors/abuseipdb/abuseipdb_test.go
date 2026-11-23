//go:build detector_unit

package abuseipdb

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "a1b1" + "d8017dc5eea1a4a6d38645a762d7a7d7158940f5b305418f9bff9579595ace6c61d154b69017"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "ABUSEIPDB_KEY=" + want + "\n",
		Want:      want,
		Negatives: []string{"abuseipdb placeholder", ""},
	})
}
