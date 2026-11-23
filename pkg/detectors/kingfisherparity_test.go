package detectors_test

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	"github.com/plenoai/pleno-dlp/pkg/detectors/catalog"
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
	rowRe := regexp.MustCompile(`^rule=(\S+) validation=(\S+) status=(covered|partial|missing|context) detector=(\S+) verified=(\S+)$`)
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
		case m[3] != "missing" && m[3] != "context" && m[4] == "-":
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
	for _, s := range []string{"covered", "partial", "missing", "context"} {
		if header[s] != got[s] {
			t.Errorf("%s=%d but %d rows", s, header[s], got[s])
		}
	}
	summary := regexp.MustCompile(`\| all rules \| (\d+) \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|`).FindStringSubmatch(doc)
	if summary == nil || summary[1] != strconv.Itoa(got["covered"]) || summary[2] != strconv.Itoa(got["partial"]) ||
		summary[3] != strconv.Itoa(got["missing"]) || summary[4] != strconv.Itoa(got["context"]) || summary[5] != strconv.Itoa(rows) {
		t.Errorf("summary table %v disagrees with the machine block", summary)
	}
}

// TestKingfisherValidatedRulesAreVerified is the verification-parity gate
// (issue #934): every rule kingfisher validates must be verified by
// pleno-dlp, either by the credited detector's own Verify ("native") or
// by a pkg/detectors/catalog check whose kind the doc records. The doc's
// verified column must agree with the live registry and catalog in both
// directions.
func TestKingfisherValidatedRulesAreVerified(t *testing.T) {
	doc := readFile(t, filepath.Join(repoRoot(t), "docs", "kingfisher-parity.md"))
	block := regexp.MustCompile("(?s)```parity-machine\n(.*?)```").FindStringSubmatch(doc)
	if block == nil {
		t.Fatal("parity-machine block not found")
	}
	verifies := map[string]bool{}
	for _, d := range detectors.All() {
		if _, ok := d.(detectors.Verifier); ok {
			verifies[d.Type().String()] = true
		}
	}
	rowRe := regexp.MustCompile(`^rule=(\S+) validation=(\S+) status=\S+ detector=(\S+) verified=(\S+)$`)
	header := map[string]int{}
	validated, verified, plenoOnly := 0, 0, 0
	inDoc := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(block[1]), "\n") {
		m := rowRe.FindStringSubmatch(line)
		if m == nil {
			if k, v, ok := strings.Cut(line, "="); ok {
				if n, err := strconv.Atoi(v); err == nil {
					header[k] = n
				}
			}
			continue
		}
		rule, validation, det, ver := m[1], m[2], m[3], m[4]
		inDoc[rule] = ver
		if validation != "-" {
			validated++
			if ver == "-" {
				t.Errorf("%s: kingfisher validates it (%s) but pleno-dlp does not verify it", rule, validation)
			} else {
				verified++
			}
		} else if ver != "-" {
			plenoOnly++
		}
		switch kind := catalog.CheckKind(rule); {
		case kind != "":
			if ver != kind {
				t.Errorf("%s: doc says verified=%s, catalog check is %s; rerun scripts/kingfisher-parity.py", rule, ver, kind)
			}
		case ver == "native":
			ok := false
			for _, name := range strings.Split(det, ",") {
				ok = ok || verifies[name]
			}
			if !ok {
				t.Errorf("%s: verified=native but no credited detector (%s) implements Verify", rule, det)
			}
		case ver != "-":
			t.Errorf("%s: verified=%s but the catalog has no check for it", rule, ver)
		}
	}
	for _, id := range catalog.VerifiedRules() {
		if _, ok := inDoc[id]; !ok {
			t.Errorf("catalog check %s is not a kingfisher rule in the parity doc", id)
		}
	}
	if header["validated"] != validated || header["verified"] != verified {
		t.Errorf("machine header validated=%d verified=%d, rows say %d/%d", header["validated"], header["verified"], validated, verified)
	}
	if header["pleno_only_verified"] != plenoOnly {
		t.Errorf("machine header pleno_only_verified=%d, rows say %d", header["pleno_only_verified"], plenoOnly)
	}
	if w := "| pleno-only verified | 0 | " + strconv.Itoa(plenoOnly) + " |"; !strings.Contains(doc, w) {
		t.Errorf("summary missing %q", w)
	}
	want := "| validated parity | " + strconv.Itoa(validated) + " | " + strconv.Itoa(verified) + " |"
	if !strings.Contains(doc, want) {
		t.Errorf("summary missing %q", want)
	}
}

// TestKingfisherParityRegenerates fails when docs/kingfisher-parity.md is
// not byte-identical to a fresh run of scripts/kingfisher-parity.py over
// the pinned kingfisher snapshot (scripts/testdata/kingfisher-rules.json),
// so rows cannot be hand-edited or go stale as detectors change (#962).
func TestKingfisherParityRegenerates(t *testing.T) {
	if testing.Short() {
		t.Skip("regenerates the parity doc with a full fixture scan")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	cmd := exec.Command(python, "scripts/kingfisher-parity.py", "--check")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("scripts/kingfisher-parity.py --check: %v\n%s", err, out)
	}
}
