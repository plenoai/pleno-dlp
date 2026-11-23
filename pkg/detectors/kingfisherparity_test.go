package detectors_test

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
)

// TestKingfisherParityDoc keeps docs/kingfisher-parity.md consistent with
// the registry: every detector it credits must be registered, every row
// must carry a known status, and the summary counts must match the rows.
// scripts/kingfisher-parity.py regenerates the doc against a kingfisher
// clone; this test is the offline half of that check (epic #817).
func TestKingfisherParityDoc(t *testing.T) {
	doc := readFile(t, filepath.Join(repoRoot(t), "docs", "kingfisher-parity.md"))
	block := regexp.MustCompile("(?s)```parity-machine\n(.*?)```").FindStringSubmatch(doc)
	if block == nil {
		t.Fatal("docs/kingfisher-parity.md: parity-machine block not found")
	}
	registered := map[string]bool{}
	for _, d := range detectors.All() {
		registered[d.Type().String()] = true
	}
	header := map[string]int{}
	got := map[string]int{}
	rows := 0
	rowRe := regexp.MustCompile(`^rule=(\S+) validation=(\S+) status=(covered|partial|missing) detector=(\S+)$`)
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(block[1]), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k != "rule" {
			if n, err := strconv.Atoi(v); err == nil {
				header[k] = n
			}
			continue
		}
		m := rowRe.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("malformed row %q", line)
			continue
		}
		rows++
		if seen[m[1]] {
			t.Errorf("rule %s listed twice", m[1])
		}
		seen[m[1]] = true
		got[m[3]]++
		switch {
		case m[3] == "missing" && m[4] != "-":
			t.Errorf("rule %s: missing rows must not name a detector (got %s)", m[1], m[4])
		case m[3] != "missing" && m[4] == "-":
			t.Errorf("rule %s: %s rows must name a detector", m[1], m[3])
		case m[4] != "-":
			for _, name := range strings.Split(m[4], ",") {
				if !registered[name] {
					t.Errorf("rule %s credits %s, which is not a registered detector; rerun scripts/kingfisher-parity.py", m[1], name)
				}
			}
		}
	}
	if header["total"] != rows {
		t.Errorf("total=%d but %d rows", header["total"], rows)
	}
	for _, s := range []string{"covered", "partial", "missing"} {
		if header[s] != got[s] {
			t.Errorf("%s=%d but %d rows", s, header[s], got[s])
		}
	}
	summary := regexp.MustCompile(`\| all rules \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|`).FindStringSubmatch(doc)
	if summary == nil || summary[1] != strconv.Itoa(got["covered"]) || summary[2] != strconv.Itoa(got["partial"]) ||
		summary[3] != strconv.Itoa(got["missing"]) || summary[4] != strconv.Itoa(rows) {
		t.Errorf("summary table %v disagrees with the machine block", summary)
	}
}
