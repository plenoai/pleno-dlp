// Package railsmasterkey detects Ruby on Rails' `config/master.key`: a
// file whose entire content is nothing but a 32-character lowercase hex
// string (Rails generates it via `SecureRandom.hex(16)`). This key
// symmetrically decrypts `config/credentials.yml.enc` (and, on older
// Rails 5.1 apps, `config/secrets.yml.enc`) — anyone who has both files
// has full access to every credential Rails' encrypted-credentials
// store holds.
//
// The Detector interface never receives the source filename, so — like
// pgpass — detection here means "content shape only": the entire chunk,
// trimmed, is exactly 32 lowercase hex characters and nothing else.
// There is no keyword to anchor on (the file carries no label of its
// own), so this is a FullChunkDetector, matching pgpass's precedent for
// "no fixed literal marker" shapes.
//
// This whole-content match is deliberately strict to bound false
// positives: it only fires when a chunk's entire content — not a
// substring of it — is the hex run. A bare MD5 checksum is the same
// length and character class, so a repo that stores a lone MD5 digest
// as an entire file's content (e.g. a `.md5` sidecar) would also match;
// that is an accepted, documented trade-off rather than an oversight —
// requiring the match to consume the whole chunk already rules out the
// far larger set of files where a 32-hex-char run merely appears
// embedded in other content.
//
// Verify is deliberately not implemented (class b): this is a local
// symmetric encryption key with no provider endpoint. Confirming it
// works would require the paired `credentials.yml.enc` (or
// `secrets.yml.enc`) ciphertext, which is not present in this chunk.
package railsmasterkey

import (
	"bytes"
	"context"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// isDegenerate rejects a hex string built from a single repeated
// character (e.g. all-zero or all-`f`), the shape a placeholder or
// test fixture is most likely to use.
func isDegenerate(s []byte) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.RailsMasterKey }

// Keywords is documentation-only — see the package doc comment for why
// dispatch is driven entirely by WantsFullChunk rather than an
// Aho-Corasick keyword hit.
func (Scanner) Keywords() []string { return []string{"master.key"} }

// WantsFullChunk opts into the FullChunkDetector path: master.key has
// no keyword to slice a vicinity window around, so the engine must hand
// this detector the whole chunk.
func (Scanner) WantsFullChunk() bool { return true }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) != 32 {
		return nil, nil
	}
	for _, c := range trimmed {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return nil, nil
		}
	}
	if isDegenerate(trimmed) {
		return nil, nil
	}
	return []detectors.Result{{
		DetectorType: detectors.RailsMasterKey,
		Raw:          bytes.Clone(trimmed),
		Redacted:     string(trimmed[:4]) + "...",
		Severity:     detectors.SeverityHigh,
	}}, nil
}

func init() {
	detectors.Register(Scanner{})
}
