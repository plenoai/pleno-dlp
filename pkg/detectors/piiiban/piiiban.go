// Package piiiban detects International Bank Account Numbers via shape
// + mod-97 checksum. Length varies per country (15..34), and the
// country prefix is two letters so we can validate both the length
// and the prefix-checksum invariant before emitting.
//
// Severity defaults to Medium via DefaultSeverity. finding_class=pii.
package piiiban

import (
	"bytes"
	"context"
	"math/big"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// ibanRe captures the shape: two-letter country, two check digits,
// then 11..30 alphanumerics, with optional spaces every 4 chars
// (the human-readable rendering). Lengths are normalised in code.
var ibanRe = regexp.MustCompile(`\b([A-Z]{2}\d{2}(?:[\s]?[A-Z0-9]){11,30})\b`)

var keywords = []string{"iban", "bic"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PIIIBAN }
func (Scanner) Keywords() []string           { return keywords }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := ibanRe.FindAll(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := make(map[string]struct{}, len(hits))
	for _, h := range hits {
		norm := normaliseIBAN(h)
		if !ibanLengthValid(norm) {
			continue
		}
		if !mod97Valid(norm) {
			continue
		}
		if _, dup := seen[norm]; dup {
			continue
		}
		seen[norm] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.PIIIBAN,
			Raw:          h,
			Redacted:     redactIBAN(norm),
			ExtraData: map[string]string{
				"finding_class": "pii",
				"pii_kind":      "iban",
				"country":       norm[:2],
			},
		})
	}
	return out, nil
}

// normaliseIBAN strips whitespace and uppercases letters.
func normaliseIBAN(b []byte) string {
	var out bytes.Buffer
	for _, c := range b {
		switch {
		case c == ' ':
			continue
		case c >= 'a' && c <= 'z':
			out.WriteByte(c - ('a' - 'A'))
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
}

// ibanLengths is the per-country length table. We only enumerate the
// commonly-issued countries; for the long tail we accept any 15..34
// length so we don't false-negative niche jurisdictions.
var ibanLengths = map[string]int{
	"DE": 22, "GB": 22, "FR": 27, "IT": 27, "ES": 24, "NL": 18,
	"BE": 16, "CH": 21, "AT": 20, "DK": 18, "SE": 24, "NO": 15,
	"FI": 18, "PL": 28, "PT": 25, "IE": 22, "LU": 20, "JP": 23,
}

func ibanLengthValid(s string) bool {
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	if want, ok := ibanLengths[s[:2]]; ok {
		return len(s) == want
	}
	return true // unknown country — fall through to mod-97 only.
}

// mod97Valid implements the IBAN check. Move the country-and-check
// digits to the end, replace letters with their digit pairs (A=10,
// B=11, ..., Z=35), and verify mod 97 == 1.
func mod97Valid(s string) bool {
	rotated := s[4:] + s[:4]
	var sb strings.Builder
	for _, c := range rotated {
		switch {
		case c >= '0' && c <= '9':
			sb.WriteRune(c)
		case c >= 'A' && c <= 'Z':
			sb.WriteString(intToString(int(c - 'A' + 10)))
		default:
			return false
		}
	}
	bi, ok := new(big.Int).SetString(sb.String(), 10)
	if !ok {
		return false
	}
	mod := new(big.Int).Mod(bi, big.NewInt(97))
	return mod.Int64() == 1
}

// intToString avoids strconv import for a 0..35 range — we only need
// to render at most two digits per letter.
func intToString(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

// redactIBAN keeps the country code + check digits and the last 4
// — enough to triage the leak without revealing the account.
func redactIBAN(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}

func init() {
	detectors.Register(Scanner{})
}
