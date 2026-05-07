// Package privatekey detects PEM-encoded private keys (RSA, EC, OpenSSH, PGP,
// DSA, Ed25519, generic PKCS8). Verification is N/A — emitting these is the
// finding.
package privatekey

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Match the begin marker, the body, and the end marker in one go. Use [\s\S]
// (any char including newline) since Go regexp's `.` excludes \n by default.
var blockRe = regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |PGP |DSA |ED25519 |ENCRYPTED |)?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |OPENSSH |PGP |DSA |ED25519 |ENCRYPTED |)?PRIVATE KEY-----`)

// Used to pull the algorithm token out of the BEGIN line for ExtraData.
var algRe = regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |PGP |DSA |ED25519 |ENCRYPTED |)?PRIVATE KEY-----`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PrivateKeyPEM }

// "PRIVATE KEY" alone is the canonical keyword — every PEM private key block
// contains it on both BEGIN and END lines.
func (Scanner) Keywords() []string { return []string{"PRIVATE KEY"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := blockRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		alg := extractAlg(m)
		// Verification of a private key requires a known peer or signing
		// challenge — out of scope. Emit unverified.
		res := detectors.Result{
			DetectorType: detectors.PrivateKeyPEM,
			Raw:          m,
			Redacted:     "-----BEGIN " + alg + "PRIVATE KEY----- (truncated)",
			ExtraData:    map[string]string{"algorithm": stringOrUnknown(alg)},
		}
		out = append(out, res)
	}
	return out, nil
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
