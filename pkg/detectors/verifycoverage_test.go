package detectors_test

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
)

// TestVerifyCoverageDoc keeps docs/verify-coverage.md honest.
//
// The doc partitions every registered DetectorType into one of three
// classes:
//
//   - (a) Verify implemented            — detector satisfies detectors.Verifier
//   - (b) unverified-by-design          — listed as class=b in the coverage-machine block
//   - (c) verifiable but not implemented — listed as class=c in the coverage-machine block
//
// The test fails on any drift:
//
//   - count totals (total / a / b / c) disagree with what we observe in registry,
//   - a registered DetectorType is not in the doc,
//   - a doc entry references a DetectorType that is not registered,
//   - a doc entry classifies a Verifier-implementing detector as b/c,
//   - a doc entry classifies a non-Verifier detector as a (a is the implicit complement;
//     listing as `class=a` is rejected to keep the doc terse),
//   - the same DetectorType appears more than once in the machine block.
//
// Adding a new detector therefore forces an explicit choice: implement
// Verify, OR list the new type as class=b with rationale, OR list it as
// class=c so the gap is tracked.
func TestVerifyCoverageDoc(t *testing.T) {
	doc, err := loadCoverageMachine(t)
	if err != nil {
		t.Fatalf("load doc: %v", err)
	}

	registered := map[string]bool{}
	registeredVerifies := map[string]bool{}
	for _, d := range detectors.All() {
		name := d.Type().String()
		if registered[name] {
			t.Errorf("registry has duplicate type %q (registry bug, not a doc problem)", name)
		}
		registered[name] = true
		_, ok := d.(detectors.Verifier)
		registeredVerifies[name] = ok
	}

	// 1. Header counts must agree with what we observe.
	gotA, gotB, gotC := 0, 0, 0
	for name := range registered {
		switch doc.classes[name] {
		case "":
			if registeredVerifies[name] {
				gotA++
			}
			// non-listed + no Verify is impossible if the doc is honest;
			// the missing-from-doc check below catches it.
		case "b":
			gotB++
		case "c":
			gotC++
		}
	}
	// Anything in registry that has Verify but is also doc-listed is a
	// classification error, surfaced below. Above we only count consistent
	// (a) — entries with Verify and not in doc.

	if doc.total != len(registered) {
		t.Errorf("doc total=%d but registry has %d detectors", doc.total, len(registered))
	}
	if doc.a != gotA {
		t.Errorf("doc a=%d but observed %d Verifier-implementing detectors not listed in machine block", doc.a, gotA)
	}
	if doc.b != gotB {
		t.Errorf("doc b=%d but observed %d entries with class=b", doc.b, gotB)
	}
	if doc.c != gotC {
		t.Errorf("doc c=%d but observed %d entries with class=c", doc.c, gotC)
	}

	// 2. Every doc entry must correspond to a registered type.
	for name, class := range doc.classes {
		if !registered[name] {
			t.Errorf("doc lists DetectorType=%q (class=%s) but it is not registered — retired without doc cleanup?", name, class)
		}
	}

	// 3. Every registered detector must be classifiable.
	//    - Verifier-implementing detectors: must NOT appear in the machine block.
	//    - Non-Verifier detectors: MUST appear with class=b or class=c.
	for name, hasVerify := range registeredVerifies {
		class, listed := doc.classes[name]
		switch {
		case hasVerify && listed:
			t.Errorf("DetectorType=%q implements Verify but doc lists class=%s — class (a) must be the implicit complement", name, class)
		case !hasVerify && !listed:
			t.Errorf("DetectorType=%q does not implement Verify but is missing from docs/verify-coverage.md (must be class=b or class=c)", name)
		}
	}

	// 4. Reject class=a entries — keep (a) as the open-set complement so
	//    the machine block stays terse. Already enforced by parser
	//    (only b/c are accepted), but assert it for good measure.
	for name, class := range doc.classes {
		if class != "b" && class != "c" {
			t.Errorf("DetectorType=%q has unexpected class=%q (only b or c allowed)", name, class)
		}
	}

	// 5. Sanity: the machine block listing should be sorted to keep diffs
	//    stable. We do not strictly require sort order to pass CI but emit
	//    a heads-up if drift looks accidental.
	if !sort.StringsAreSorted(doc.orderedNames) {
		t.Logf("note: coverage-machine block entries are not lexicographically sorted; consider re-sorting on next edit")
	}
}

type coverageDoc struct {
	total        int
	a            int
	b            int
	c            int
	classes      map[string]string // DetectorType name → class ("b" or "c")
	orderedNames []string
}

func loadCoverageMachine(t *testing.T) (*coverageDoc, error) {
	t.Helper()
	path := findDoc(t)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	const fence = "```coverage-machine"
	out := &coverageDoc{classes: map[string]string{}}
	in := false
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case !in && strings.HasPrefix(line, fence):
			in = true
		case in && strings.HasPrefix(line, "```"):
			in = false
		case in:
			if err := parseLine(line, out); err != nil {
				return nil, err
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseLine(line string, out *coverageDoc) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	switch {
	case strings.HasPrefix(line, "total="):
		n, err := strconv.Atoi(strings.TrimPrefix(line, "total="))
		if err != nil {
			return err
		}
		out.total = n
	case strings.HasPrefix(line, "a="):
		n, err := strconv.Atoi(strings.TrimPrefix(line, "a="))
		if err != nil {
			return err
		}
		out.a = n
	case strings.HasPrefix(line, "b="):
		n, err := strconv.Atoi(strings.TrimPrefix(line, "b="))
		if err != nil {
			return err
		}
		out.b = n
	case strings.HasPrefix(line, "c="):
		n, err := strconv.Atoi(strings.TrimPrefix(line, "c="))
		if err != nil {
			return err
		}
		out.c = n
	case strings.HasPrefix(line, "type="):
		name, class, err := parseTypeLine(line)
		if err != nil {
			return err
		}
		if _, dup := out.classes[name]; dup {
			return &dupErr{name: name}
		}
		out.classes[name] = class
		out.orderedNames = append(out.orderedNames, name)
	}
	return nil
}

func parseTypeLine(line string) (name, class string, err error) {
	// "type=X class=y" — two whitespace-separated key=value pairs.
	parts := strings.Fields(line)
	for _, p := range parts {
		switch {
		case strings.HasPrefix(p, "type="):
			name = strings.TrimPrefix(p, "type=")
		case strings.HasPrefix(p, "class="):
			class = strings.TrimPrefix(p, "class=")
		}
	}
	if name == "" {
		return "", "", &parseErr{line: line, why: "missing type="}
	}
	if class != "b" && class != "c" {
		return "", "", &parseErr{line: line, why: "class must be b or c, got " + class}
	}
	return name, class, nil
}

type parseErr struct {
	line string
	why  string
}

func (e *parseErr) Error() string {
	return "verify-coverage.md parse: " + e.why + " in line: " + e.line
}

type dupErr struct {
	name string
}

func (e *dupErr) Error() string {
	return "verify-coverage.md: DetectorType=" + e.name + " listed twice in machine block"
}

func findDoc(t *testing.T) string {
	t.Helper()
	// Walk up from CWD looking for docs/verify-coverage.md. The test runs
	// from inside pkg/detectors when invoked as `go test ./pkg/detectors`,
	// from the repo root when invoked as `go test ./...`, and from the
	// package dir when invoked via `go test`.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, "docs", "verify-coverage.md")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("docs/verify-coverage.md not found from %s", dir)
	return ""
}
