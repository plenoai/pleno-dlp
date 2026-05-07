// Package piissn detects US Social Security Numbers in xxx-xx-xxxx form.
// The detector deliberately rejects reserved / invalid ranges to suppress
// the most common false-positive shapes (test data 000-00-0000, the
// infamous 078-05-1120 / 219-09-9999 / 999-xx-xxxx blocks).
//
// Severity defaults to Medium via DefaultSeverity. Marked finding_class=pii.
package piissn

import (
	"context"
	"regexp"
	"strconv"
)

import "github.com/plenoai/pleno-dlp/pkg/detectors"

// ssnRe matches xxx-xx-xxxx with literal hyphens. We do NOT match the
// no-hyphen 9-digit form: that would fire on every order number, every
// 9-digit numeric ID, and the FP rate destroys the detector's
// usefulness. Operators who must catch the no-hyphen variant should
// add a custom rule.
var ssnRe = regexp.MustCompile(`\b(\d{3})-(\d{2})-(\d{4})\b`)

// Keywords are deliberately empty-ish — SSN-shaped strings appear
// frequently without a "ssn" keyword nearby (forms, log lines, CSV
// headers). We list the common label words anyway so chunks lacking
// any of them aren't a sure miss; the engine's keyword filter then
// gates by substring presence and we re-validate the regex shape.
var keywords = []string{"ssn", "social security", "social-security"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PIIUSSSN }
func (Scanner) Keywords() []string           { return keywords }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := ssnRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := make(map[string]struct{}, len(hits))
	for _, h := range hits {
		full := string(h[0])
		area := string(h[1])
		group := string(h[2])
		serial := string(h[3])
		if !validSSN(area, group, serial) {
			continue
		}
		if _, dup := seen[full]; dup {
			continue
		}
		seen[full] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.PIIUSSSN,
			Raw:          h[0],
			Redacted:     "***-**-" + serial,
			ExtraData: map[string]string{
				"finding_class": "pii",
				"pii_kind":      "us-ssn",
			},
		})
	}
	return out, nil
}

// validSSN rejects ranges the SSA never assigns. The list is from
// publicly published SSA assignment rules; missing entries here mean
// false-positives, not false-negatives, so the policy is "stricter is
// safer". Operators who scan EU-equivalent IDs should reach for the
// custom rule loader.
func validSSN(area, group, serial string) bool {
	a, _ := strconv.Atoi(area)
	g, _ := strconv.Atoi(group)
	s, _ := strconv.Atoi(serial)
	switch {
	case a == 0, g == 0, s == 0:
		return false // any zero block is reserved.
	case a == 666, a >= 900:
		return false // SSA never issues these area numbers.
	case area == "078" && group == "05" && serial == "1120":
		return false // Woolworth's 1938 wallet-card SSN.
	case area == "219" && group == "09" && serial == "9999":
		return false // the Social Security pamphlet example.
	}
	return true
}

func init() {
	detectors.Register(Scanner{})
}
