package detectors_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
)

// TestPublishedCountsMatchSource is the single CI gate for every
// human-facing "N detectors" / "N sources" claim published in
// README.md, website/index.html, docs/comparison.md, and
// docs/verify-coverage.md. See docs/counts.md for what each number
// counts and why. In short:
//
//   - The pleno-dlp detector-type count (and its verified/unverified
//     split) is derived here, at test time, from detectors.All() — the
//     exact registry `detectors list` and the scan engine use. It is
//     never hand-typed twice; every doc must match the registry.
//   - The pleno-dlp source count is derived from pkg/sources/catalog
//     by cmd/pleno-dlp/cmd/sources_sync_test.go, which pins it to
//     docs/comparison.md's "Scan sources" cell. That cell and the two
//     competitor counts (trufflehog detectors, gitleaks rules — measured
//     from third-party binaries, not derivable here) are extracted from
//     docs/comparison.md as canonical text and cross-checked against
//     every other file that quotes them, docs/counts.md included.
//
// Add, remove, or reclassify a detector and this test breaks until every
// quoted location is updated in the same PR — that is the intended gate.
func TestPublishedCountsMatchSource(t *testing.T) {
	root := repoRoot(t)

	all := detectors.All()
	total := len(all)
	verified := 0
	for _, d := range all {
		if _, ok := d.(detectors.Verifier); ok {
			verified++
		}
	}
	unverified := total - verified

	comparison := readFile(t, filepath.Join(root, "docs", "comparison.md"))

	sources, ok := extractInt(comparison, regexp.MustCompile(`\|\s*Scan sources\s*\|\s*(\d+)\s*\|`))
	if !ok {
		t.Fatalf("docs/comparison.md: could not find the \"Scan sources\" table cell — " +
			"has the coverage-counts table been reworded? update this test's regex")
	}
	trufflehogDetectors, ok := extractInt(comparison, regexp.MustCompile(`\|\s*Detectors / rules\s*\|\s*\d+\s*\|\s*(\d+)\s*\|\s*\d+\s*\|`))
	if !ok {
		t.Fatalf("docs/comparison.md: could not find trufflehog's column in the \"Detectors / rules\" row")
	}
	gitleaksRules, ok := extractInt(comparison, regexp.MustCompile(`\|\s*Detectors / rules\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*(\d+)\s*\|`))
	if !ok {
		t.Fatalf("docs/comparison.md: could not find gitleaks's column in the \"Detectors / rules\" row")
	}
	measuredDate, ok := extractString(comparison, regexp.MustCompile(`produced by running the three tools side by side on (\d{4}-\d{2}-\d{2})`))
	if !ok {
		t.Fatalf("docs/comparison.md: could not find the \"produced by running ... on YYYY-MM-DD\" methodology sentence")
	}

	// docs/comparison.md must agree with itself and with the registry.
	checkInt(t, "docs/comparison.md", `"Detectors / rules" row, pleno-dlp column`, comparison,
		regexp.MustCompile(`\|\s*Detectors / rules\s*\|\s*(\d+)\s*\|\s*\d+\s*\|\s*\d+\s*\|`), total)
	checkInt(t, "docs/comparison.md", `"Live-verification capable" row, verified count`, comparison,
		regexp.MustCompile(`\|\s*Live-verification capable\s*\|\s*(\d+)\s*\(\+\d+ unverified-by-design`), verified)
	checkInt(t, "docs/comparison.md", `"Live-verification capable" row, unverified count`, comparison,
		regexp.MustCompile(`\|\s*Live-verification capable\s*\|\s*\d+\s*\(\+(\d+) unverified-by-design`), unverified)
	checkInt(t, "docs/comparison.md", `"trufflehog ships N detector packages vs M" — M`, comparison,
		regexp.MustCompile(`trufflehog ships \d+ detector packages vs\s+(\d+)\s*\(long tail`), total)
	checkInt(t, "docs/comparison.md", `"pleno-dlp's N sources lead on SaaS-document surfaces"`, comparison,
		regexp.MustCompile(`pleno-dlp's (\d+) sources lead on SaaS-document`), sources)

	// docs/verify-coverage.md
	coverage := readFile(t, filepath.Join(root, "docs", "verify-coverage.md"))
	checkInt(t, "docs/verify-coverage.md", `"Total = N" prose`, coverage,
		regexp.MustCompile(`Total = (\d+):`), total)
	checkInt(t, "docs/verify-coverage.md", `"(a) Verify implemented — N detectors" heading`, coverage,
		regexp.MustCompile(`## \(a\) Verify implemented — (\d+) detectors`), verified)
	checkInt(t, "docs/verify-coverage.md", `"(b) Unverified-by-design — N detectors" heading`, coverage,
		regexp.MustCompile(`## \(b\) Unverified-by-design — (\d+) detectors`), unverified)
	checkInt(t, "docs/verify-coverage.md", "machine block total=", coverage,
		regexp.MustCompile(`(?m)^total=(\d+)$`), total)
	checkInt(t, "docs/verify-coverage.md", "machine block a=", coverage,
		regexp.MustCompile(`(?m)^a=(\d+)$`), verified)
	checkInt(t, "docs/verify-coverage.md", "machine block b=", coverage,
		regexp.MustCompile(`(?m)^b=(\d+)$`), unverified)

	// docs/counts.md — the definitions page carries "Current value" lines
	// of its own; per its closing rule, an unenforced count is exactly the
	// drift it exists to prevent (§2 sat at a stale 24 for weeks because
	// nothing read it).
	counts := readFile(t, filepath.Join(root, "docs", "counts.md"))
	checkInt(t, "docs/counts.md", `§1 "Current value: N total"`, counts,
		regexp.MustCompile(`\*\*Current value:\*\* (\d+) total`), total)
	checkInt(t, "docs/counts.md", `§1 verified split`, counts,
		regexp.MustCompile(`\*\*Current value:\*\* \d+ total \((\d+) verified`), verified)
	checkInt(t, "docs/counts.md", `§1 unverified split`, counts,
		regexp.MustCompile(`\*\*Current value:\*\* \d+ total \(\d+ verified, (\d+) unverified-by-design\)`), unverified)
	checkInt(t, "docs/counts.md", `§2 "Current value: N wired sources"`, counts,
		regexp.MustCompile(`\*\*Current value:\*\* (\d+) wired sources`), sources)
	checkInt(t, "docs/counts.md", `§3 trufflehog count`, counts,
		regexp.MustCompile(`\*\*Current value:\*\* trufflehog (\d+), gitleaks`), trufflehogDetectors)
	checkInt(t, "docs/counts.md", `§3 gitleaks count`, counts,
		regexp.MustCompile(`\*\*Current value:\*\* trufflehog \d+, gitleaks (\d+)`), gitleaksRules)
	if !strings.Contains(counts, measuredDate) {
		t.Errorf("docs/counts.md: §3 quotes competitor counts without the %s measurement date from docs/comparison.md", measuredDate)
	}

	// README.md
	readme := readFile(t, filepath.Join(root, "README.md"))
	checkInt(t, "README.md", `"N built-in detector types"`, readme,
		regexp.MustCompile(`(\d+) built-in detector types`), total)

	// website/index.html
	website := readFile(t, filepath.Join(root, "website", "index.html"))
	checkInt(t, "website/index.html", `meta description "pleno-dlp detects N types"`, website,
		regexp.MustCompile(`pleno-dlp detects (\d+) types of leaked credentials`), total)
	checkInt(t, "website/index.html", `og:description "N detectors"`, website,
		regexp.MustCompile(`content="(\d+) detectors\. Live verification`), total)
	checkInt(t, "website/index.html", `hero "N detector types, M sources" — N`, website,
		regexp.MustCompile(`(\d+) detector types, \d+ sources, one static Go binary`), total)
	checkInt(t, "website/index.html", `hero "N detector types, M sources" — M`, website,
		regexp.MustCompile(`\d+ detector types, (\d+) sources, one static Go binary`), sources)
	checkInt(t, "website/index.html", `"N of M detectors check the issuing provider" — N (verified)`, website,
		regexp.MustCompile(`(\d+) of \d+ detectors check the issuing provider`), verified)
	checkInt(t, "website/index.html", `"N of M detectors check the issuing provider" — M (total)`, website,
		regexp.MustCompile(`\d+ of (\d+) detectors check the issuing provider`), total)
	checkInt(t, "website/index.html", `bench row "pleno-dlp<small>N detectors</small>"`, website,
		regexp.MustCompile(`pleno-dlp<small>(\d+) detectors</small>`), total)
	checkInt(t, "website/index.html", `bench row "trufflehog<small>N detectors</small>"`, website,
		regexp.MustCompile(`trufflehog<small>(\d+) detectors</small>`), trufflehogDetectors)
	checkInt(t, "website/index.html", `bench row "gitleaks<small>N regex rules</small>"`, website,
		regexp.MustCompile(`gitleaks<small>(\d+) regex rules</small>`), gitleaksRules)

	if !strings.Contains(website, measuredDate) {
		t.Errorf("website/index.html: competitor detector/rule counts (trufflehog %d, gitleaks %d) "+
			"are quoted without their measurement date; docs/comparison.md says they were measured "+
			"%s — the website must say so too (they are a point-in-time snapshot of a third-party "+
			"binary, not something this repo can keep live)", trufflehogDetectors, gitleaksRules, measuredDate)
	}
}

// repoRoot walks up from the working directory looking for go.mod. Tests
// under this package can run with a CWD of pkg/detectors (package-scoped
// `go test`) or the module root (`go test ./...`), so this must not
// assume either.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("could not find repo root (go.mod) walking up from %s", dir)
	return ""
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// extractInt returns the first capture group of re matched against
// content, parsed as an int. ok is false if re does not match.
func extractInt(content string, re *regexp.Regexp) (int, bool) {
	s, ok := extractString(content, re)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

func extractString(content string, re *regexp.Regexp) (string, bool) {
	m := re.FindStringSubmatch(content)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// checkInt extracts an integer claim from content via re and reports a
// test failure naming the exact file/claim and the correct value if it
// disagrees with want. A non-matching pattern is reported the same way a
// wrong number would be, since prose changing enough to break the regex
// is itself a form of this doc going stale relative to the test that is
// supposed to guard it.
func checkInt(t *testing.T, file, claim, content string, re *regexp.Regexp, want int) {
	t.Helper()
	got, ok := extractInt(content, re)
	if !ok {
		t.Errorf("%s: could not find %s (pattern %s did not match — "+
			"wording changed? update pkg/detectors/counts_test.go's regex, "+
			"then re-verify it still catches drift)", file, claim, re.String())
		return
	}
	if got != want {
		t.Errorf("%s: %s says %d, want %d (see docs/counts.md for the source of truth)", file, claim, got, want)
	}
}
