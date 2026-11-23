package all

import (
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// minDispatchKeywordLen is the shortest keyword a window detector may
// register (#1015). A shorter keyword hits on almost every input: the
// engine then visits a hit and merges a vicinity span for most bytes, and
// a whole-blob gate built on keywords (#1014) can never skip anything.
const minDispatchKeywordLen = 3

// shortKeywordReasons documents each keyword below the floor. The only
// accepted reason is that the keyword is already the longest literal
// every match of the detector must contain, so no longer keyword keeps
// the same findings. Each of these was checked against the detector's
// regexp syntax tree; the rest of the match is a byte class, not a
// literal.
var shortKeywordReasons = map[string]string{
	"Twilio/ac":       `account SID \bAC[a-f0-9]{32}\b: "AC" is the only literal`,
	"TwilioAPIKey/sk": `API key SID \bSK[0-9a-fA-F]{32}\b: "SK" is the only literal`,
	"Plivo/ma":        `auth ID \b(?:MA|SA)[A-Z0-9]{18}\b: the required literal set is {MA, SA}`,
	"Plivo/sa":        `auth ID \b(?:MA|SA)[A-Z0-9]{18}\b: the required literal set is {MA, SA}`,
	"Bitwarden/0.":    `access token \b0\.[a-f0-9-]{36}\.…: "0." is the longest literal prefix; later literals are single bytes`,
	"ZAI/.":           `[0-9A-Fa-f]{32}\.[0-9A-Za-z]{16}: "." is the only literal; the format's hexRunBeforeDot prefilter rejects windows instead`,
}

// TestKeywordFloor fails when a window detector, or a format attached to
// one, registers a keyword shorter than minDispatchKeywordLen without a
// documented reason, and when a documented exception goes stale.
// FullChunkDetectors are exempt: the engine never dispatches them from
// keyword hits and leaves their keywords out of the prefilter.
func TestKeywordFloor(t *testing.T) {
	t.Parallel()
	used := map[string]bool{}
	for _, d := range detectors.All() {
		if fc, ok := d.(detectors.FullChunkDetector); ok && fc.WantsFullChunk() {
			continue
		}
		for _, kw := range detectors.KeywordsWithFormats(d) {
			if len(kw) >= minDispatchKeywordLen {
				continue
			}
			key := d.Type().String() + "/" + strings.ToLower(kw)
			if _, ok := shortKeywordReasons[key]; !ok {
				t.Errorf("%s registers keyword %q (%d bytes, floor %d); use the longest literal every match must contain, or document why none is longer in shortKeywordReasons", d.Type(), kw, len(kw), minDispatchKeywordLen)
				continue
			}
			used[key] = true
		}
	}
	for key := range shortKeywordReasons {
		if !used[key] {
			t.Errorf("shortKeywordReasons[%q] no longer matches a registered keyword; remove it", key)
		}
	}
}
