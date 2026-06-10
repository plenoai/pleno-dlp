// Package privatekey detects PEM-encoded private keys (RSA, EC, OpenSSH,
// PGP, DSA, Ed25519, generic PKCS8).
//
// Two-stage finding:
//
//  1. detection — regex-locate every PEM private-key block in the chunk
//     and emit one Result per block. Always runs.
//
//  2. blast-radius enrichment — local public-key derivation (always),
//     plus optional Certificate Transparency lookup (only when --verify
//     is set on the engine). Each step folds metadata into
//     Result.ExtraData:
//
//     - pubkey_algorithm        e.g. "RSA", "EC", "ED25519", "OPENSSH"
//     - pubkey_fingerprint_sha256  hex SPKI digest, suitable for crt.sh
//     - ssh_fingerprint         "SHA256:<base64-no-pad>" for SSH keys
//     - pem_encrypted           "true" when the PEM was passphrase-protected
//     - pem_unlocked_with       the passphrase that unlocked the wordlist (only when present)
//     - ct_status               match | no-match | error
//     - blast_radius_domains    comma-joined CT-logged domains the key signs
//     - blast_radius_cert_count number of CT-logged certs found
//
// When CT lookup returns one or more domain matches, the finding is
// promoted to Verified=true. The severity model in
// detectors.DefaultSeverity then escalates the finding from Medium to
// Critical via the verified path.
//
// Privacy contract: the private-key body NEVER leaves the host. Only
// the SHA-256 of the public key's SubjectPublicKeyInfo is transmitted
// upstream, and only to crt.sh, and only when the operator opted in
// via --verify. The fingerprint is itself a public artefact (it
// appears in every certificate the key has ever signed); transmitting
// it does not leak anything that wasn't already in the public CT log
// when the cert was issued.
package privatekey

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/privatekey/blastradius"
)

// Match the begin marker, the body, and the end marker in one go. Use [\s\S]
// (any char including newline) since Go regexp's `.` excludes \n by default.
// The optional ` BLOCK` suffix covers PGP armor: `-----BEGIN PGP PRIVATE KEY BLOCK-----`.
var blockRe = regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |PGP |DSA |ED25519 |ENCRYPTED |)?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (RSA |EC |OPENSSH |PGP |DSA |ED25519 |ENCRYPTED |)?PRIVATE KEY(?: BLOCK)?-----`)

// Used to pull the algorithm token out of the BEGIN line as a fallback when
// the PEM body fails to parse (corrupted block, truncated paste).
var algRe = regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |PGP |DSA |ED25519 |ENCRYPTED |)?PRIVATE KEY(?: BLOCK)?-----`)

// Scanner is the privatekey detector. The struct carries a CT client and
// passphrase wordlist that are wired up lazily — the zero value works
// for unit tests and the engine, falling back to the embedded wordlist
// and a default crt.sh client respectively.
type Scanner struct {
	// CT, when non-nil, is the Certificate Transparency client used by
	// Verify. Tests inject a mock; production scans use the lazily-
	// initialised default created by ctClient().
	CT *blastradius.CTClient

	// Passphrases, when non-nil, overrides the embedded wordlist used
	// to attempt unlocking encrypted PEMs. Empty = use embedded list.
	// Operators with org-specific defaults (e.g. a known build-system
	// passphrase) prepend their candidates here.
	Passphrases []string
}

func (Scanner) Type() detectors.DetectorType { return detectors.PrivateKeyPEM }

// "PRIVATE KEY" alone is the canonical keyword — every PEM private key block
// contains it on both BEGIN and END lines.
func (Scanner) Keywords() []string { return []string{"PRIVATE KEY"} }

// WantsFullChunk opts this detector out of the engine's vicinity-slice
// dispatch path. blockRe matches BEGIN...END pairs that can span many
// kilobytes (RSA-8192 PEM ≈ 6.4 KB, PGP keyrings larger still), and
// the 2-KiB vicinity radius routinely splits the two anchors into
// separate slices on real-world key files. Paying the full-window
// regex cost on this detector is the right trade — its keyword is
// specific enough that prefilter dispatch is rare.
func (Scanner) WantsFullChunk() bool { return true }

// FromData locates every PEM private-key block, derives the public-key
// fingerprint locally, and attempts to unlock encrypted blocks with the
// embedded passphrase wordlist. When verify=true and a fingerprint was
// derived, FromData also queries Certificate Transparency and folds
// the discovered domains into ExtraData. The CT call is per-block —
// each block hits crt.sh at most once.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := blockRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		res := s.deriveResult(m)
		if verify {
			s.applyCTLookup(ctx, &res)
		}
		out = append(out, res)
	}
	return out, nil
}

// Verify is the Verifier-interface entry point used by callers that
// invoke detectors directly (rather than via FromData with verify=true).
// It re-derives the fingerprint from secret and queries CT. The boolean
// return is "did CT have at least one cert for this key?" — same shape
// every other Verifier in the codebase uses.
func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	pk, err := blastradius.Derive([]byte(secret))
	if err != nil {
		if errors.Is(err, blastradius.ErrEncrypted) {
			pk2, _, derr := blastradius.DeriveWithPassphrase([]byte(secret), s.passphrases())
			if derr != nil || pk2.SPKISHA256Hex == "" {
				return false, nil
			}
			return s.lookupCT(ctx, pk2.SPKISHA256Hex)
		}
		return false, err
	}
	if pk.SPKISHA256Hex == "" {
		// PGP / DSA / unsupported algorithm — local derivation
		// succeeded but produced no fingerprint we can correlate.
		return false, nil
	}
	return s.lookupCT(ctx, pk.SPKISHA256Hex)
}

// lookupCT calls the CT log client and translates its result into the
// (verified, error) shape expected by the Verifier interface. A non-
// empty match list = verified.
func (s Scanner) lookupCT(ctx context.Context, fingerprint string) (bool, error) {
	matches, err := s.ctClient().Lookup(ctx, fingerprint)
	if err != nil {
		return false, err
	}
	return len(matches) > 0, nil
}

// applyCTLookup queries Certificate Transparency for the result's
// fingerprint and writes the outcome into ExtraData. Behaviour:
//
//   - fingerprint missing (e.g. PGP, encrypted-and-unbroken) → no-op
//   - CT match → Verified=true, blast_radius_domains, blast_radius_cert_count set
//   - CT empty → blast_radius_domains absent, ct_status="no-match"
//   - transport error → VerificationErr set, ct_status="error"
func (s Scanner) applyCTLookup(ctx context.Context, res *detectors.Result) {
	fingerprint := res.ExtraData["pubkey_fingerprint_sha256"]
	if fingerprint == "" {
		return
	}
	matches, err := s.ctClient().Lookup(ctx, fingerprint)
	if err != nil {
		res.VerificationErr = err
		res.ExtraData["ct_status"] = "error"
		return
	}
	if len(matches) == 0 {
		res.ExtraData["ct_status"] = "no-match"
		return
	}
	domains := blastradius.Domains(matches)
	res.Verified = true
	res.ExtraData["ct_status"] = "match"
	res.ExtraData["blast_radius_cert_count"] = strconv.Itoa(len(matches))
	if len(domains) > 0 {
		res.ExtraData["blast_radius_domains"] = strings.Join(domains, ",")
	}
}

// deriveResult assembles the detection-time Result for a single PEM
// block. All work here is local — CT lookup is deferred to applyCTLookup.
//
// Encrypted blocks are decoded twice: once to flag the encryption,
// once after a wordlist unlock. The unlock is attempted unconditionally
// because it is purely local and never leaks the key body — and a
// successful unlock is a security-critical signal (a deploy key behind
// "password" is a deploy key with no real protection).
func (s Scanner) deriveResult(block []byte) detectors.Result {
	algFromHeader := stringOrUnknown(extractAlg(block))
	res := detectors.Result{
		DetectorType: detectors.PrivateKeyPEM,
		Raw:          block,
		Redacted:     "-----BEGIN " + extractAlg(block) + "PRIVATE KEY----- (truncated)",
		ExtraData:    map[string]string{"algorithm": algFromHeader},
	}

	pk, err := blastradius.Derive(block)
	switch {
	case err == nil:
		applyPubkey(res.ExtraData, pk)
	case errors.Is(err, blastradius.ErrEncrypted):
		res.ExtraData["pem_encrypted"] = "true"
		if pk2, pw, derr := blastradius.DeriveWithPassphrase(block, s.passphrases()); derr == nil {
			applyPubkey(res.ExtraData, pk2)
			res.ExtraData["pem_unlocked_with"] = pw
			// Severity escalation: an "encrypted" key with a guessable
			// passphrase is exactly as exposed as an unencrypted key.
			// Pin to High to reflect that, overriding the default
			// Medium for unverified PrivateKeyPEM hits.
			res.Severity = detectors.SeverityHigh
		}
	}
	return res
}

// applyPubkey folds a derived PublicKey into the ExtraData map. Keys
// are namespaced (`pubkey_*`, `ssh_*`) so output formatters and
// downstream consumers can identify them by prefix.
func applyPubkey(extra map[string]string, pk blastradius.PublicKey) {
	if pk.Algorithm != "" {
		extra["pubkey_algorithm"] = pk.Algorithm
	}
	if pk.SPKISHA256Hex != "" {
		extra["pubkey_fingerprint_sha256"] = pk.SPKISHA256Hex
	}
	if pk.SSHFingerprint != "" {
		extra["ssh_fingerprint"] = pk.SSHFingerprint
	}
}

// passphrases returns the wordlist to use for encrypted-PEM unlocking,
// preferring the per-Scanner override if set, falling back to the
// embedded default. The default is computed once and cached via
// sync.Once because reading the embedded wordlist is non-trivial
// (string scan + slice allocation) and the engine may invoke this
// thousands of times per scan.
func (s Scanner) passphrases() []string {
	if len(s.Passphrases) > 0 {
		return s.Passphrases
	}
	return defaultPassphrases()
}

var (
	defaultPassphrasesOnce  sync.Once
	defaultPassphrasesValue []string
)

func defaultPassphrases() []string {
	defaultPassphrasesOnce.Do(func() {
		defaultPassphrasesValue = blastradius.DefaultPassphrases()
	})
	return defaultPassphrasesValue
}

// ctClient returns the Scanner's configured CT client or a default one.
func (s Scanner) ctClient() *blastradius.CTClient {
	if s.CT != nil {
		return s.CT
	}
	return blastradius.NewCTClient()
}

func extractAlg(block []byte) string {
	m := algRe.FindSubmatch(block)
	if len(m) < 2 {
		return ""
	}
	return string(m[1])
}

func stringOrUnknown(s string) string {
	if s == "" {
		return "PKCS8"
	}
	// Strip trailing space ("RSA " -> "RSA").
	for len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	return s
}

func init() {
	detectors.Register(Scanner{})
}
