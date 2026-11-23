package git

import (
	"strings"
	"testing"
)

// TestSynthStreamMatchesShardedAndGit pins that the newest-first stream
// walk (one and several raw segments) emits exactly the chunks of the
// sharded in-process renderer and of git's own `log -p` rendering.
func TestSynthStreamMatchesShardedAndGit(t *testing.T) {
	for _, packed := range []bool{false, true} {
		dir := buildShardRepo(t)
		if packed {
			// Packed objects take the in-process object store.
			gitRun(t, dir, "repack", "-adq", "--depth=50", "--window=50")
		}
		checkSynthStreamParity(t, dir)
	}
}

func checkSynthStreamParity(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("PLENO_DLP_GIT_PATCH_RENDER", "git")
	want := strings.Join(chunkKeys(t, dir, 1), "\n")

	t.Setenv("PLENO_DLP_GIT_PATCH_RENDER", "inprocess")
	t.Setenv("PLENO_DLP_GIT_SYNTH_STREAM", "0")
	if got := strings.Join(chunkKeys(t, dir, 1), "\n"); got != want {
		t.Fatalf("sharded in-process chunks differ\nwant:\n%s\ngot:\n%s", want, got)
	}
	t.Setenv("PLENO_DLP_GIT_SYNTH_STREAM", "")
	for _, seg := range []int{1 << 30, 3, 1} {
		old := nativeStreamSegmentCommits
		nativeStreamSegmentCommits = seg
		got := strings.Join(chunkKeys(t, dir, 1), "\n")
		nativeStreamSegmentCommits = old
		if got != want {
			t.Fatalf("stream chunks (segment %d) differ\nwant:\n%s\ngot:\n%s", seg, want, got)
		}
	}
}
