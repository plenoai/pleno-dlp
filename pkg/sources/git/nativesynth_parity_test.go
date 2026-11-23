package git

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// renderNativeSynth renders args (patch-mode log arguments) through the
// in-process renderer.
func renderNativeSynth(t testing.TB, s *Source, args []string, stdin string) []byte {
	t.Helper()
	ctx := context.Background()
	res, err := startNativeSynthRes(ctx, "git", s.repoAbs)
	if err != nil {
		t.Fatal(err)
	}
	defer res.close()
	cmd := exec.Command("git", nativeRawArgs(args)...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = nativeGitEnv()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w := bufio.NewWriter(&out)
	r := &nativeSynthLog{ctx: ctx, source: s, gitBin: "git", patchArgs: args, res: res, out: w}
	if err := r.run(stdout); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func renderGitPatch(t testing.TB, args []string, stdin string) []byte {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = nativeGitEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// firstDiff reports the commit and surrounding text of the first mismatch.
func firstDiff(want, got []byte) string {
	n := min(len(want), len(got))
	i := 0
	for i < n && want[i] == got[i] {
		i++
	}
	start := bytes.LastIndexByte(want[:i], nativeRecordSeparator)
	if start < 0 {
		start = 0
	}
	lo := max(i-300, start)
	return "commit context:\n" + string(want[start:min(start+60, len(want))]) +
		"\n--- git\n" + string(want[lo:min(i+300, len(want))]) +
		"\n--- render\n" + string(got[lo:min(i+300, len(got))])
}

// TestNativeSynthParityCorpus compares the renderer with `git log -p` over
// a real repository named by PLENO_DLP_SYNTH_PARITY_REPO (benchmark corpora).
func TestNativeSynthParityCorpus(t *testing.T) {
	repo := os.Getenv("PLENO_DLP_SYNTH_PARITY_REPO")
	if repo == "" {
		t.Skip("PLENO_DLP_SYNTH_PARITY_REPO not set")
	}
	for _, th := range []bool{false, true} {
		s := &Source{repoAbs: repo, trufflehogCompatible: th, binaryBlobs: &binaryBlobCache{}, diffAttrs: &diffAttrCache{}}
		args := s.nativeLogArgs()
		want := renderGitPatch(t, args, "HEAD\n")
		got := renderNativeSynth(t, s, args, "HEAD\n")
		if !bytes.Equal(want, got) {
			// A diff driver (e.g. "*.rb diff=ruby") changes only the
			// function context after a hunk header's closing "@@",
			// which the parser ignores; compare without it.
			nw, ng := stripHunkContext(want), stripHunkContext(got)
			if bytes.Equal(nw, ng) {
				t.Logf("trufflehog=%v: identical except hunk-header function context", th)
				continue
			}
			want, got = nw, ng
			t.Fatalf("trufflehog=%v: rendered %d bytes, git %d bytes\n%s", th, len(got), len(want), firstDiff(want, got))
		}
		t.Logf("trufflehog=%v: %d bytes identical", th, len(want))
	}
}

var _ = io.EOF

var hunkContext = regexp.MustCompile(`(?m)^(@@ -[0-9,]+ \+[0-9,]+ @@).*$`)

func stripHunkContext(b []byte) []byte { return hunkContext.ReplaceAll(b, []byte("$1")) }

func TestNativeSynthDump(t *testing.T) {
	repo := os.Getenv("PLENO_DLP_SYNTH_DUMP_REPO")
	if repo == "" {
		t.Skip()
	}
	s := &Source{repoAbs: repo, binaryBlobs: &binaryBlobCache{}, diffAttrs: &diffAttrCache{}}
	args := s.nativeLogArgs()
	_ = os.WriteFile(os.Getenv("PLENO_DLP_SYNTH_DUMP_OUT")+".git", renderGitPatch(t, args, "HEAD\n"), 0o644)
	_ = os.WriteFile(os.Getenv("PLENO_DLP_SYNTH_DUMP_OUT")+".synth", renderNativeSynth(t, s, args, "HEAD\n"), 0o644)
}
