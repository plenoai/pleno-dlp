package detectors_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
)

// TestPublishedCountsMatchSource is the single CI gate for every
// human-facing "N detectors" / "N sources" claim published in
// README.md, website/index.html, and docs/verify-coverage.md. See
// docs/counts.md for what each number counts and why. In short:
//
//   - The pleno-dlp detector-type count (and its verified/unverified
//     split) is derived here, at test time, from detectors.All() — the
//     exact registry `detectors list` and the scan engine use. It is
//     never hand-typed twice; every doc must match the registry.
//   - The pleno-dlp source count is derived from pkg/sources/catalog
//     by cmd/pleno-dlp/cmd/sources_sync_test.go, which pins it to
//     docs/counts.md's "Current value" line. The runtime counts are
//     cross-checked against every public file that quotes them.
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

	counts := readFile(t, filepath.Join(root, "docs", "counts.md"))
	sources, ok := extractInt(counts, regexp.MustCompile(`\*\*Current value:\*\* (\d+) wired sources`))
	if !ok {
		t.Fatalf("docs/counts.md: could not find the \"Current value: N wired sources\" line")
	}

	// docs/counts.md carries the canonical current values.
	checkInt(t, "docs/counts.md", `detector total`, counts,
		regexp.MustCompile(`\*\*Current value:\*\* (\d+) total`), total)
	checkInt(t, "docs/counts.md", `verified split`, counts,
		regexp.MustCompile(`\*\*Current value:\*\* \d+ total \((\d+) verified`), verified)
	checkInt(t, "docs/counts.md", `unverified split`, counts,
		regexp.MustCompile(`\*\*Current value:\*\* \d+ total \(\d+ verified, (\d+) unverified-by-design\)`), unverified)

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
