package cmd

import (
	"fmt"
	"io"
	"sort"

	"github.com/spf13/pflag"

	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// registerSuppressionFlags adds the baseline, inline-pragma, and skip flags
// shared by `scan` and `protect`. All of them feed the single
// engine.Allowlist policy so suppression has one counter, one audit path
// (--show-suppressed), and one ordering in the sink chain (#812).
func registerSuppressionFlags(fs *pflag.FlagSet) {
	fs.StringVar(&scanOpts.baselinePath, "baseline", "",
		"path to a baseline file (see 'pleno-dlp baseline create'); findings whose fingerprint is recorded there are suppressed")
	fs.BoolVar(&scanOpts.noInlineAllow, "no-inline-allow", false,
		"ignore inline pleno-dlp:allow / pleno-dlp:allow-next-line pragmas (audit mode: annotated secrets are reported)")
	fs.StringArrayVar(&scanOpts.inlineAllowTokens, "inline-allow-token", nil,
		"additional same-line inline-allow comment token, e.g. NOSONAR or 'secret-scan: ignore' (repeatable; added to pleno-dlp:allow, kingfisher:ignore, gitleaks:allow)")
	fs.StringArrayVar(&scanOpts.skipRegex, "skip-regex", nil,
		"suppress findings whose raw secret matches this Go regexp (repeatable)")
	fs.StringArrayVar(&scanOpts.skipWord, "skip-word", nil,
		"suppress findings whose raw secret contains this word, case-insensitively (repeatable)")
}

// loadSuppressionPolicy builds the allowlist from .pleno-allow.json (or
// --allowlist), --skip-regex, --skip-word, --baseline, and the inline
// pragma setting. It always returns a non-nil policy so inline pragmas are
// honored even without an allowlist file.
func loadSuppressionPolicy() (*engine.Allowlist, error) {
	a, err := loadAllowlistMaybe(scanOpts.allowlistPath)
	if err != nil {
		return nil, err
	}
	if a == nil {
		a = &engine.Allowlist{}
	}
	a.HonorInline = !scanOpts.noInlineAllow
	var extra []engine.AllowlistEntry
	for _, rx := range scanOpts.skipRegex {
		extra = append(extra, engine.AllowlistEntry{Reason: "--skip-regex", RawRegex: rx})
	}
	for _, w := range scanOpts.skipWord {
		if w == "" {
			return nil, fmt.Errorf("--skip-word: empty word would suppress every finding")
		}
		extra = append(extra, engine.AllowlistEntry{Reason: "--skip-word", RawContains: w})
	}
	if err := a.Add(extra...); err != nil {
		return nil, fmt.Errorf("skip flags: %w", err)
	}
	if scanOpts.baselinePath != "" {
		b, err := engine.LoadBaselineFile(scanOpts.baselinePath)
		if err != nil {
			return nil, err
		}
		a.AddFingerprints(b.Fingerprints()...)
	}
	return a, nil
}

// reportSuppressions prints one stderr line per suppression reason, e.g.
// "allowlist: suppressed 2 finding(s)" and "baseline: suppressed 5 finding(s)".
func reportSuppressions(w io.Writer, s engine.Sink) {
	counts := engine.SuppressedByReason(s)
	reasons := make([]string, 0, len(counts))
	for r := range counts {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		if counts[r] > 0 {
			fmt.Fprintf(w, "%s: suppressed %d finding(s)\n", r, counts[r])
		}
	}
}
