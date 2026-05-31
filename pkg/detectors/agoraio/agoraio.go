// Package agoraio detects Agora.io realtime app ID + app certificate
// pairs near the `agora` keyword. Both halves are 32-hex strings.
//
// Unverified by design — Agora authenticates via offline-signed RTC
// tokens; the App Certificate is consumed only to HMAC-sign tokens
// client/server-side and is never presented to an Agora endpoint as an
// auth credential. (Agora's RESTful API authenticates with a separate
// Customer ID + Customer Secret pair, not the App ID/App Certificate
// this detector captures.) There is therefore no credential probe we
// can hit; class b stands.
//
// The raw 32-hex shape is identical to an MD5 hash, so without anchoring
// it produces heavy false positives (ETags, checksums, lockfile integrity
// hashes, truncated git SHAs) and a combinatorial N*(N-1) pairing
// explosion. To stay precise this detector:
//   - requires each matched hex to sit within 40 bytes of an Agora-
//     specific label token (app_id / app certificate / agora / ...),
//   - classifies each hit as an id-labelled or cert-labelled candidate
//     and only pairs an id with a cert (no cross-join of every hex),
//   - applies a Shannon entropy floor (32-char lowercase hex caps at
//     4.0 bits/char; ~3.0 drops repeated-nibble / low-variety lookalikes),
//   - rejects uniform or sequential hex (all-zero, 0123...) and skips
//     candidates whose nearest label is a checksum/ETag term.
package agoraio

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var idRe = regexp.MustCompile(`\b([0-9a-f]{32})\b`)

// labelVicinity is how close (in bytes) an Agora-specific label token must
// be to a hex candidate. Tightened from the previous 256-byte gate: at 40
// bytes a label and its value live on the same assignment / JSON line, which
// is where real `app_id = <hex>` / `"appCertificate": "<hex>"` shapes sit,
// while two unrelated MD5s sharing a paragraph with the word "agora" no
// longer qualify.
const labelVicinity = 40

// minEntropy gates out low-variety hex (all-zero ETags, repeated-nibble
// checksums). Real random App Certificates sit near the 4.0 ceiling.
const minEntropy = 3.0

// idLabels mark a candidate as the App ID half. certLabels mark the App
// Certificate half. agoraGenericLabels (just "agora") qualify a candidate
// for vicinity but do not assign a role on their own.
var (
	idLabels    = []string{"app_id", "appid", "app id", "app-id"}
	certLabels  = []string{"app certificate", "app_cert", "app-cert", "appcertificate", "appcert", "certificate", "cert"}
	agoraLabels = []string{"agora"}
	// excludeLabels suppress checksum/ETag/lockfile contexts: a hex whose
	// nearest label is one of these is almost certainly not a credential.
	excludeLabels = []string{"md5", "sha", "hash", "etag", "checksum", "digest", "integrity", "cache", "commit", "blob"}
)

type role int

const (
	roleNone role = iota
	roleID
	roleCert
)

type candidate struct {
	token string
	role  role
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AgoraIO }

func (Scanner) Keywords() []string { return []string{"agora"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := idRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	var ids, certs []candidate
	seenTok := map[string]struct{}{}
	for _, h := range hits {
		start, end := h[2], h[3]
		tok := string(data[start:end])
		if _, dup := seenTok[tok]; dup {
			continue
		}
		// Entropy + lookalike gates: drop all-zero / sequential / repeated-
		// nibble hex regardless of context.
		if !detectors.HasMinEntropy(tok, minEntropy) || isUniformOrSequential(tok) {
			continue
		}
		// Exclusion gate: a candidate whose vicinity is dominated by a
		// checksum/ETag term is suppressed.
		if hasLabelNear(lower, start, end, excludeLabels) {
			continue
		}
		// Require an Agora-specific label in vicinity at all.
		if !hasLabelNear(lower, start, end, agoraLabels) &&
			!hasLabelNear(lower, start, end, idLabels) &&
			!hasLabelNear(lower, start, end, certLabels) {
			continue
		}
		seenTok[tok] = struct{}{}
		switch classify(lower, start, end) {
		case roleID:
			ids = append(ids, candidate{token: tok, role: roleID})
		case roleCert:
			certs = append(certs, candidate{token: tok, role: roleCert})
		default:
			// No id/cert role but agora-labelled: treat as eligible for
			// either side so a value-only pair near `agora` still emits,
			// but only against an oppositely-typed peer.
			ids = append(ids, candidate{token: tok, role: roleNone})
			certs = append(certs, candidate{token: tok, role: roleNone})
		}
	}

	// Pair id-side with cert-side only. This eliminates the combinatorial
	// cross-join: a lone hex never pairs with itself, and two same-role
	// (e.g. two id-labelled) hexes never pair.
	out := make([]detectors.Result, 0)
	seenPair := map[string]struct{}{}
	for _, idC := range ids {
		for _, certC := range certs {
			if idC.token == certC.token {
				continue
			}
			// Require at least one side to carry an explicit role so two
			// roleNone candidates (value-only, no id/cert label) do not pair.
			if idC.role == roleNone && certC.role == roleNone {
				continue
			}
			pair := idC.token + ":" + certC.token
			if _, dup := seenPair[pair]; dup {
				continue
			}
			seenPair[pair] = struct{}{}
			out = append(out, detectors.Result{
				DetectorType: detectors.AgoraIO,
				Raw:          []byte(idC.token),
				RawV2:        []byte(pair),
				Redacted:     redact(idC.token),
			})
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// classify assigns a role from the *nearest* id/cert label within
// labelVicinity. Distance-based rather than precedence-based so that two
// adjacent values (id then cert on the same line) each bind to their own
// label instead of both grabbing whichever set is checked first.
func classify(lower string, start, end int) role {
	idDist, idOK := nearestLabelDist(lower, start, end, idLabels)
	certDist, certOK := nearestLabelDist(lower, start, end, certLabels)
	switch {
	case idOK && certOK:
		if idDist <= certDist {
			return roleID
		}
		return roleCert
	case idOK:
		return roleID
	case certOK:
		return roleCert
	default:
		return roleNone
	}
}

// nearestLabelDist returns the byte distance from [start,end) to the closest
// occurrence of any label within labelVicinity. Distance is measured from
// the candidate edges to the nearest label-token boundary.
func nearestLabelDist(lower string, start, end int, labels []string) (int, bool) {
	from := start - labelVicinity
	if from < 0 {
		from = 0
	}
	to := end + labelVicinity
	if to > len(lower) {
		to = len(lower)
	}
	best := -1
	for _, kw := range labels {
		// Scan every occurrence of kw inside the window.
		base := from
		for {
			rel := strings.Index(lower[base:to], kw)
			if rel < 0 {
				break
			}
			pos := base + rel
			labelEnd := pos + len(kw)
			var d int
			switch {
			case labelEnd <= start:
				d = start - labelEnd
			case pos >= end:
				d = pos - end
			default:
				d = 0 // overlaps candidate
			}
			if best < 0 || d < best {
				best = d
			}
			base = pos + 1
			if base >= to {
				break
			}
		}
	}
	if best < 0 {
		return 0, false
	}
	return best, true
}

// hasLabelNear reports whether any label appears within labelVicinity bytes
// of [start,end).
func hasLabelNear(lower string, start, end int, labels []string) bool {
	from := start - labelVicinity
	if from < 0 {
		from = 0
	}
	to := end + labelVicinity
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range labels {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// isUniformOrSequential rejects degenerate hex: all identical chars, or a
// strictly ascending/descending consecutive run (0123..., fedc...).
func isUniformOrSequential(t string) bool {
	if len(t) == 0 {
		return true
	}
	allSame := true
	for i := 1; i < len(t); i++ {
		if t[i] != t[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}
	asc, desc := true, true
	for i := 1; i < len(t); i++ {
		if t[i] != t[i-1]+1 {
			asc = false
		}
		if t[i] != t[i-1]-1 {
			desc = false
		}
	}
	return asc || desc
}

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
