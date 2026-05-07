// Package piicc detects credit card numbers via shape + Luhn checksum.
// The Luhn gate is essential: without it, every 16-digit numeric ID
// (order numbers, IMEIs, RFIDs) would fire. With it, we reject ~90%
// of the FP space at zero false-negative cost — every real card
// passes Luhn by definition.
//
// Severity defaults to Medium via DefaultSeverity. Marked
// finding_class=pii. No Verify path (PCI rules forbid sending card
// numbers anywhere outside an issuer relationship).
package piicc

import (
	"bytes"
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// ccRe captures runs of 13–19 digits with optional `-`/space
// separators. Card length covers all major networks (13 = old Visa,
// 14 = Diners, 15 = Amex, 16 = Visa/MC/Discover, 19 = JCB tail).
// We strip separators in code before Luhn-checking so format
// variations don't cause misses.
var ccRe = regexp.MustCompile(`\b(?:\d[\s\-]?){12,18}\d\b`)

var keywords = []string{"card", "credit", "visa", "mastercard", "amex", "discover", "jcb"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PIICreditCard }
func (Scanner) Keywords() []string           { return keywords }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := ccRe.FindAll(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := make(map[string]struct{}, len(hits))
	for _, h := range hits {
		digits := stripNonDigits(h)
		if len(digits) < 13 || len(digits) > 19 {
			continue
		}
		if !luhnValid(digits) {
			continue
		}
		key := string(digits)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.PIICreditCard,
			Raw:          h,
			Redacted:     redactCC(digits),
			ExtraData: map[string]string{
				"finding_class": "pii",
				"pii_kind":      "credit-card",
				"network":       guessNetwork(digits),
			},
		})
	}
	return out, nil
}

// stripNonDigits returns only the digit bytes from b. Used to
// normalise separator variants ("4111-1111-1111-1111", "4111 1111
// 1111 1111", "4111111111111111") before Luhn-checking.
func stripNonDigits(b []byte) []byte {
	out := bytes.Buffer{}
	for _, c := range b {
		if c >= '0' && c <= '9' {
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}

// luhnValid implements the standard mod-10 checksum every issued card
// satisfies. Constant-time for fixed-length inputs; doesn't allocate.
func luhnValid(digits []byte) bool {
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// redactCC keeps the network-identifying first 6 (BIN) and the last
// 4 — the PCI-compliant rendering for analytics. Anything between
// becomes asterisks.
func redactCC(digits []byte) string {
	if len(digits) < 10 {
		return string(digits)
	}
	prefix := digits[:6]
	suffix := digits[len(digits)-4:]
	mid := bytes.Repeat([]byte("*"), len(digits)-10)
	return string(prefix) + string(mid) + string(suffix)
}

// guessNetwork returns a short label for the issuing network. Helps
// triage know whether a leak is consumer or corporate. Pure pattern
// match — no BIN database lookup.
func guessNetwork(digits []byte) string {
	if len(digits) == 0 {
		return "unknown"
	}
	switch {
	case digits[0] == '4':
		return "visa"
	case len(digits) >= 2 && digits[0] == '5' && digits[1] >= '1' && digits[1] <= '5':
		return "mastercard"
	case len(digits) >= 2 && digits[0] == '3' && (digits[1] == '4' || digits[1] == '7'):
		return "amex"
	case len(digits) >= 4 && string(digits[:4]) == "6011":
		return "discover"
	case len(digits) >= 2 && digits[0] == '3' && (digits[1] == '0' || digits[1] == '6' || digits[1] == '8'):
		return "diners"
	case len(digits) >= 4 && (string(digits[:4]) == "3528" || string(digits[:4]) == "3529"):
		return "jcb"
	}
	return "unknown"
}

func init() {
	detectors.Register(Scanner{})
}
