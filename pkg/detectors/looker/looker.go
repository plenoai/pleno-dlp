// Package looker detects Looker API3 client_id + client_secret pairs.
// Paired credential — Raw=client_id, RawV2=client_id+":"+client_secret.
//
// Unverified by design (class b). The matched pair IS a valid credential
// for Looker's POST /api/4.0/login, but live verification is infeasible
// here: the Looker host is per-tenant and is not encoded in the 20-char
// client_id, nor reliably present in the chunk. Looker is frequently
// self-hosted on custom domains / port 19999, so any fixed-host guess
// (e.g. *.looker.com) could probe the wrong tenant and produce a wrong
// Verified verdict. The Verifier interface here is Verify(ctx, secret)
// with no apiBase channel to inject a per-instance host, so verify is
// genuinely impractical until per-instance-host plumbing exists.
//
// Because the token shape (20 alphanumeric chars) is extremely common,
// the detector anchors each candidate to a Looker API3 credential field
// name (client_id / client_secret / api3), gates on Shannon entropy, and
// excludes pure-hex / pure-decimal lookalikes (commit SHAs, numeric IDs)
// to keep the false-positive rate low.
package looker

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// fieldRe anchors a 20-char base62 token directly to a client_id /
// client_secret / api3 field name, so a lone 20-char ID merely sitting
// near the BI-product word "looker" no longer fires. The first capture
// group records which field the token was attached to (id vs secret),
// the second captures the token itself.
//
// Examples that match:
//
//	client_id=abcdef0123456789abcd
//	client_secret: "fedcba9876543210fedc"
//	api3_client_id => abcdef0123456789abcd
var fieldRe = regexp.MustCompile(`(?i)(?:api3[_-]?)?client[_-]?(id|secret)["'\s:=>(){}\[\]-]{0,4}([A-Za-z0-9]{20})\b`)

// minEntropy: 20-char base62 strings have an entropy ceiling near 6.0
// bits/char; real client_id / client_secret values sit comfortably above
// 3.5. The gate drops padded zeros, repeated chars, and decimal-only IDs.
const minEntropy = 3.5

// contextRadius is the maximum byte distance between a candidate field
// match and a Looker-API-specific context token. Tighter than the old
// generic 256-byte "looker" substring window so pages that merely mention
// the Looker product don't trip the detector.
const contextRadius = 128

// contextKeywords are Looker-API-specific markers, not the bare product
// name. Presence of one near the candidate raises confidence that the
// 20-char tokens are API3 credentials rather than incidental hashes.
var contextKeywords = []string{
	"client_id", "client_secret", "clientid", "clientsecret",
	"api3", "looker_sdk", "lookersdk", "/api/4.0", "/api/3.1", "looker",
}

var pureHexRe = regexp.MustCompile(`^[0-9a-fA-F]{20}$`)
var pureDecimalRe = regexp.MustCompile(`^[0-9]{20}$`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Looker }

func (Scanner) Keywords() []string { return []string{"looker"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := fieldRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	var clientID, clientSecret string
	for _, h := range hits {
		field := strings.ToLower(string(data[h[2]:h[3]]))
		tok := string(data[h[4]:h[5]])
		if !validCandidate(tok) {
			continue
		}
		if !nearKeyword(lower, h[4], h[5]) {
			continue
		}
		switch field {
		case "id":
			if clientID == "" {
				clientID = tok
			}
		case "secret":
			if clientSecret == "" {
				clientSecret = tok
			}
		}
		if clientID != "" && clientSecret != "" && clientID != clientSecret {
			break
		}
	}
	if clientID == "" || clientSecret == "" || clientID == clientSecret {
		return nil, nil
	}
	return []detectors.Result{{
		DetectorType: detectors.Looker,
		Raw:          []byte(clientID),
		RawV2:        []byte(clientID + ":" + clientSecret),
		Redacted:     redact(clientID),
	}}, nil
}

// validCandidate rejects low-entropy lookalikes and pure-hex / pure-decimal
// runs (commit-SHA fragments, numeric IDs) that are not Looker credentials.
func validCandidate(tok string) bool {
	if pureHexRe.MatchString(tok) || pureDecimalRe.MatchString(tok) {
		return false
	}
	return detectors.HasMinEntropy(tok, minEntropy)
}

func nearKeyword(lower string, start, end int) bool {
	from := start - contextRadius
	if from < 0 {
		from = 0
	}
	to := end + contextRadius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
