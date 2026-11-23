//go:build detector_unit

package influxdb

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "xWwc" + "9sV7RdBULHS89uADHo7aTAVjZjqsVzwjV5KJYATEWuo9Y7mUjjUcqfgDwNYhJN4Szxn9oAD59u4cRLqMAZ=="

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "influxdb token = " + want + "\n",
		Want:      want,
		Negatives: []string{"influx placeholder", ""},
	})
}
