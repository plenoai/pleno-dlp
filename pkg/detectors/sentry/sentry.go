// Package sentry detects Sentry DSN URLs (https://<32 hex>@<host>/<project>).
// Verification is impossible — Sentry has no public DSN-validate endpoint, and
// the DSN itself doubles as ingest credential, so probing it would mint a
// fake event in the leaked project. We always emit Verified=false.
package sentry

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// DSN: scheme://<32-hex public key>@<host>/<project id>. The public key is
// the secret to triage — anyone holding the DSN can write events into the
// owning project.
var dsnRe = regexp.MustCompile(`\b(https?://[a-f0-9]{32}@[a-z0-9.-]+/\d+)\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Sentry }

// "sentry.io" catches public-cloud DSNs; "@sentry" catches self-hosted ones
// where the host is something like "sentry.example.com".
func (Scanner) Keywords() []string { return []string{"sentry"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := dsnRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		dsn := string(m)
		if _, dup := seen[dsn]; dup {
			continue
		}
		seen[dsn] = struct{}{}
		// Verify is intentionally not implemented — see package doc.
		out = append(out, detectors.Result{
			DetectorType: detectors.Sentry,
			Raw:          []byte(dsn),
			Redacted:     redact(dsn),
		})
	}
	return out, nil
}

func redact(dsn string) string {
	// Keep "https://" plus the first 6 hex chars of the public key — enough
	// to distinguish without leaking the full ingest credential.
	cut := 8 + 6
	if len(dsn) <= cut {
		return dsn
	}
	return dsn[:cut] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
