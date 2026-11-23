package git

import (
	"bytes"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitUnifiedHunks renders a -> b with the real git binary under the same
// diff options nativeLogArgs passes and returns only the hunk text.
func gitUnifiedHunks(t *testing.T, dir string, a, b []byte) []byte {
	t.Helper()
	pa, pb := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(pa, a, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pb, b, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "-c", "diff.suppressBlankEmpty=false", "diff", "--no-index", "--text",
		"--no-color", "--no-ext-diff", "--no-textconv", "--no-indent-heuristic",
		"--inter-hunk-context=0", "--diff-algorithm=myers", "--unified=3", pa, pb)
	cmd.Env = nativeGitEnv()
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
			t.Fatalf("git diff: %v", err)
		}
	}
	if i := bytes.Index(out, []byte("\n@@ ")); i >= 0 {
		return out[i+1:]
	}
	return nil
}

func randomLines(r *rand.Rand, n int, vocab []string) []byte {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(vocab[r.Intn(len(vocab))])
		b.WriteByte('\n')
	}
	s := b.String()
	if r.Intn(4) == 0 && len(s) > 0 {
		s = s[:len(s)-1]
	}
	return []byte(s)
}

func mutate(r *rand.Rand, base []byte, vocab []string) []byte {
	lines := strings.SplitAfter(string(base), "\n")
	var out []string
	for _, l := range lines {
		switch r.Intn(10) {
		case 0:
		case 1:
			out = append(out, vocab[r.Intn(len(vocab))]+"\n", l)
		case 2:
			out = append(out, vocab[r.Intn(len(vocab))]+"\n")
		default:
			out = append(out, l)
		}
	}
	return []byte(strings.Join(out, ""))
}

func TestXDiffMatchesGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	r := rand.New(rand.NewSource(983))
	vocabs := [][]string{
		{"a", "b", "c", "", "}", "func x() {", "  return"},
		{"x", "y"},
		{"alpha beta", "gamma", "_under", "$dollar", "\tindented", "1234", "", " ", "{", "}"},
	}
	var x xdiffer
	iterations := 400
	if testing.Short() {
		iterations = 80
	}
	for i := 0; i < iterations; i++ {
		vocab := vocabs[i%len(vocabs)]
		n := r.Intn(60)
		if i%25 == 0 {
			n = 600 + r.Intn(1500)
		}
		a := randomLines(r, n, vocab)
		b := mutate(r, a, vocab)
		if i%7 == 0 {
			b = randomLines(r, r.Intn(80), vocab)
		}
		if i%11 == 0 {
			a = nil
		}
		want := gitUnifiedHunks(t, dir, a, b)
		got, _ := x.unified(nil, a, b)
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d mismatch\na=%q\nb=%q\n--- git\n%s\n--- port\n%s", i, a, b, want, got)
		}
	}
}
