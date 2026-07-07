// Package puttyprivatekey detects PuTTY's `.ppk` private-key file
// format: a `PuTTY-User-Key-File-2:`/`-3:` header line through the
// trailing `Private-MAC:` line, e.g.:
//
//	PuTTY-User-Key-File-2: ssh-rsa
//	Encryption: none
//	Comment: imported-openssh-key
//	Public-Lines: 6
//	<base64 public key>
//	Private-Lines: 14
//	<base64 private key material>
//	Private-MAC: <hex>
//
// This is a distinct wire format from PEM: PuTTY never emits a
// `-----BEGIN ... PRIVATE KEY-----` armor line, so privatekey's blockRe
// never matches a `.ppk` file and there is no overlap between the two
// detectors — this one is new coverage, not a duplicate.
//
// Like privatekey, this is a FullChunkDetector: an RSA-4096 `.ppk` can
// run several kilobytes of base64 across many `Public-Lines`/
// `Private-Lines`, comfortably exceeding the engine's 2 KiB vicinity
// radius, so the whole-chunk regex pass is required to keep the header
// and the closing `Private-MAC:` line in the same match.
//
// Verify is deliberately not implemented (class b). PrivateKeyPEM
// upgrades to class (a) by deriving the public-key fingerprint locally
// and correlating it against Certificate Transparency — the same
// technique would apply here in principle, but requires first
// converting PPK's key-specific field layout (`ssh-rsa`/`ssh-dss`/
// `ssh-ed25519`/`ecdsa-sha2-*`) into the DER `SubjectPublicKeyInfo`
// privatekey's blastradius package expects. That conversion is real,
// non-trivial parsing work and is out of scope for this batch; a
// PPK-to-DER bridge into blastradius is a natural follow-up to
// reclassify this detector into (a).
package puttyprivatekey

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// blockRe matches from the PuTTY header line through the closing
// Private-MAC line. (?s) lets `.` cross newlines; the header token
// alone (`PuTTY-User-Key-File-2:`/`-3:`) is specific enough that a
// non-greedy body match to the first `Private-MAC:` line is safe — real
// .ppk files contain exactly one such block.
var blockRe = regexp.MustCompile(
	`(?s)PuTTY-User-Key-File-[23]:[ \t]*\S+.*?Private-MAC:[ \t]*[0-9a-fA-F]+`,
)

var algRe = regexp.MustCompile(`PuTTY-User-Key-File-[23]:[ \t]*(\S+)`)
var encryptionRe = regexp.MustCompile(`(?m)^Encryption:[ \t]*(\S+)[ \t]*$`)
var formatVersionRe = regexp.MustCompile(`PuTTY-User-Key-File-([23]):`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PuTTYPrivateKey }

// Keywords is documentation-only — see WantsFullChunk below.
func (Scanner) Keywords() []string {
	return []string{"PuTTY-User-Key-File-2:", "PuTTY-User-Key-File-3:"}
}

// WantsFullChunk opts this detector into the FullChunkDetector path;
// see the package doc comment for why the vicinity-slice window is too
// small for larger keys.
func (Scanner) WantsFullChunk() bool { return true }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	matches := blockRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		out = append(out, deriveResult(m))
	}
	return out, nil
}

func deriveResult(block []byte) detectors.Result {
	extra := map[string]string{}
	if am := algRe.FindSubmatch(block); len(am) >= 2 {
		extra["algorithm"] = string(am[1])
	}
	if vm := formatVersionRe.FindSubmatch(block); len(vm) >= 2 {
		extra["format_version"] = string(vm[1])
	}
	encrypted := "false"
	if em := encryptionRe.FindSubmatch(block); len(em) >= 2 {
		if string(em[1]) != "none" {
			encrypted = "true"
			extra["encryption"] = string(em[1])
		}
	}
	extra["ppk_encrypted"] = encrypted

	sev := detectors.SeverityHigh
	if encrypted == "true" {
		// An encrypted .ppk still leaked the identity of a key pair and
		// its comment, but the private-key material itself needs the
		// passphrase to use — one notch below an unencrypted key.
		sev = detectors.SeverityMedium
	}

	return detectors.Result{
		DetectorType: detectors.PuTTYPrivateKey,
		Raw:          block,
		Redacted:     "PuTTY-User-Key-File (" + extra["algorithm"] + ", truncated)",
		ExtraData:    extra,
		Severity:     sev,
	}
}

func init() {
	detectors.Register(Scanner{})
}
