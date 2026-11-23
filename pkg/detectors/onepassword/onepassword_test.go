//go:build detector_unit

package onepassword

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify/tokenverifytest"
)

// The fixture is split so repository secret scanning does not flag it.
var want = "ops_" + "eyJiPvx6nrTNNurUEncjeikzLHxgBCDmfZES4dwWfxrmWcLeaYjVsZHQHtbBk3DAafbFKFakidDw96x2qwGnP4F6bUgmmzgFnuTgbSyDKqSkbnborabVJx7EPhJHZTHb8DyxXpGJq9KfzhcxdufR8oCw57CbsJ9zPTKfoM7xf7ArmtyFvvfoSUjzogxxx2eUjBkkg6WKkda2o8eivAPXBYGkJumcFcAj42koMrje7LJXV5Lb6hiyC4SBgRipSNK6hfgijHB"

func TestContract(t *testing.T) {
	tokenverifytest.Check(t, Detector, tokenverifytest.Case{
		Input:     "" + want + "\n",
		Want:      want,
		Negatives: []string{"ops_eyj placeholder", ""},
	})
}
