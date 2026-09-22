package git

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// gitExec runs git inside dir; tests here need the real binary because
// partial-clone filters are a native-git transport feature.
func gitExec(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// buildFilteredClone builds a source repo containing one blob above the
// emission ceiling (50 MiB of text), then mirror-clones it with
// --filter=blob:limit=50m. The filter floor therefore clears every emission
// ceiling, so the omitted add is a legitimate partial-clone boundary.
// Returns the clone path.
func buildFilteredClone(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	gitExec(t, src, "init", "-q")
	big := strings.Repeat("PROMISOR-OMITTED-LINE\n", 51*1024*1024/22)
	if err := os.WriteFile(filepath.Join(src, "big.txt"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("alpha\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitExec(t, src, "add", "-A")
	gitExec(t, src, "commit", "-qm", "c1")
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("alpha\nbeta\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitExec(t, src, "commit", "-qam", "c2")
	// blob:limit filters only work when the transport permits filtering.
	cfgPath := filepath.Join(src, ".git", "config")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, append(cfg, []byte("[uploadpack]\n\tallowFilter = true\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	clone := filepath.Join(t.TempDir(), "clone")
	gitExec(t, t.TempDir(), "clone", "-q", "--mirror", "--no-local",
		"--filter=blob:limit=50m", "file://"+src, clone)
	return clone
}

func TestRepoPromisorFilteredDetectsFilter(t *testing.T) {
	clone := buildFilteredClone(t)
	filteredRepo, err := gogit.PlainOpen(clone)
	if err != nil {
		t.Fatal(err)
	}
	s := &Source{repoAbs: clone}
	if !s.repoPromisorFiltered(filteredRepo) {
		t.Fatal("promisor-filtered clone was not detected")
	}
	repo, _ := buildRepo(t, []commitSpec{{files: map[string]string{"a.txt": "x"}, msg: "c1"}})
	plainRepo, err := gogit.PlainOpen(repo)
	if err != nil {
		t.Fatal(err)
	}
	plain := &Source{repoAbs: repo}
	if plain.repoPromisorFiltered(plainRepo) {
		t.Fatal("ordinary repo reported as promisor-filtered")
	}
}

// TestChunks_OfflineWalkerSkipsOmittedBlobs verifies the promisor walk emits
// every locally present change, omits the filtered blob without failing, and
// never fetches it (GIT_NO_LAZY_FETCH is baked into nativeGitEnv).
func TestChunks_OfflineWalkerSkipsOmittedBlobs(t *testing.T) {
	clone := buildFilteredClone(t)
	s := &Source{}
	mustInit(t, s, Config{Repo: clone, AllBranches: true})

	got, err := drain(t, s, 30*time.Second)
	// The missing 51 MiB add could hold scannable text, so coverage must
	// degrade instead of checkpointing — the locally present blobs still emit.
	if err != nil {
		var degraded *engine.DegradedError
		if !errors.As(err, &degraded) {
			t.Fatalf("Chunks: %v", err)
		}
	}
	var files []string
	var sawAlpha, sawBeta bool
	for _, c := range got {
		if c.SourceMetadata.Git == nil {
			continue
		}
		files = append(files, c.SourceMetadata.Git.File)
		data := string(c.Data)
		if strings.Contains(data, "alpha") {
			sawAlpha = true
		}
		if strings.Contains(data, "beta") {
			sawBeta = true
		}
		if strings.Contains(data, "PROMISOR-OMITTED-LINE") {
			t.Fatalf("promisor-omitted blob content was emitted for %s", c.SourceMetadata.Git.File)
		}
	}
	if !sawAlpha || !sawBeta {
		t.Fatalf("missing local content: sawAlpha=%v sawBeta=%v files=%v", sawAlpha, sawBeta, files)
	}
	for _, f := range files {
		if f == "big.txt" {
			t.Fatalf("filtered blob produced a chunk: %v", files)
		}
	}
	if s.IncrementalState() != nil {
		t.Fatalf("degraded coverage advanced the checkpoint: %v", s.IncrementalState())
	}
}

// TestChunks_OfflineWalkerPreservesMetadata checks commit/author/file/line
// metadata survives the offline path unchanged.
func TestChunks_OfflineWalkerPreservesMetadata(t *testing.T) {
	clone := buildFilteredClone(t)
	s := &Source{}
	mustInit(t, s, Config{Repo: clone, AllBranches: true})

	got, err := drain(t, s, 30*time.Second)
	if err != nil {
		var degraded *engine.DegradedError
		if !errors.As(err, &degraded) {
			t.Fatalf("Chunks: %v", err)
		}
	}
	if len(got) == 0 {
		t.Fatal("no chunks emitted")
	}
	for _, c := range got {
		meta := c.SourceMetadata.Git
		if meta == nil {
			t.Fatal("chunk missing git metadata")
		}
		if meta.Commit == "" || meta.File == "" || meta.Repository != clone {
			t.Fatalf("incomplete metadata: %+v", meta)
		}
		if meta.Author != "test" || meta.Email != "test@example.com" {
			t.Fatalf("author metadata mismatch: %+v", meta)
		}
	}
}

// TestChunksOfflineDirect exercises the offline native walker on the
// filtered clone regardless of whether this host's git qualifies for the
// native fast path.
func TestChunksOfflineDirect(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not on PATH")
	}
	clone := buildFilteredClone(t)
	s := &Source{}
	mustInit(t, s, Config{Repo: clone, AllBranches: true})
	s.repoAbs = clone

	repo, err := gogit.PlainOpen(clone)
	if err != nil {
		t.Fatalf("open clone: %v", err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("head: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ch := make(chan *sources.Chunk, 64)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.chunksOffline(ctx, repo, gitBin, []plumbing.Hash{head.Hash()}, nil, ch)
		close(ch)
	}()
	var got []*sources.Chunk
	for c := range ch {
		got = append(got, c)
	}
	if err := <-errCh; err != nil {
		var degraded *engine.DegradedError
		if !errors.As(err, &degraded) {
			t.Fatalf("chunksOffline: %v", err)
		}
	}
	var sawAlpha, sawBeta bool
	for _, c := range got {
		if strings.Contains(string(c.Data), "alpha") {
			sawAlpha = true
		}
		if strings.Contains(string(c.Data), "beta") {
			sawBeta = true
		}
		if strings.Contains(string(c.Data), "PROMISOR-OMITTED-LINE") {
			t.Fatal("omitted blob content emitted")
		}
	}
	if !sawAlpha || !sawBeta {
		t.Fatalf("missing local content: %d chunks", len(got))
	}
}

// reviewClone mirror-clones src with the given partial-clone filter.
func reviewClone(t *testing.T, src, filter string) string {
	t.Helper()
	gitExec(t, src, "config", "uploadpack.allowFilter", "true")
	dst := filepath.Join(t.TempDir(), "mirror")
	cmd := exec.Command("git", "clone", "--mirror", "--filter="+filter, "--", "file://"+filepath.ToSlash(src), dst)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clone: %v %s", err, out)
	}
	return dst
}

// TestOfflineLargeBlobDiffCoverage: a one-line append to a 51 MiB text file
// is in-scope diff content even though the blob exceeds the clone filter;
// the filtered walk must find it or report degraded coverage with the prior
// checkpoint retained — a clean checkpoint is not acceptable.
func TestOfflineLargeBlobDiffCoverage(t *testing.T) {
	requireNativeGit(t)
	filler := strings.Repeat(strings.Repeat("x", 1023)+"\n", 51*1024)
	const marker = "review_canary_new_line_only"
	src, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"large.txt": filler}, msg: "base"},
		{files: map[string]string{"large.txt": filler + marker + "\n"}, msg: "append canary"},
	})
	dst := reviewClone(t, src, "blob:limit=52428800")
	seed, err := json.Marshal(newIncrementalState([]plumbing.Hash{plumbing.NewHash(hashes[0])}))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, dir string }{{"complete", src}, {"filtered", dst}} {
		t.Run(c.name, func(t *testing.T) {
			s := &Source{}
			mustInit(t, s, Config{Repo: c.dir})
			if err := s.SetIncrementalState(seed); err != nil {
				t.Fatal(err)
			}
			got, err := drain(t, s, 30*time.Second)
			found := false
			for _, chunk := range got {
				found = found || strings.Contains(string(chunk.Data), marker)
			}
			t.Logf("chunks=%d marker=%t err=%v state=%s", len(got), found, err, s.IncrementalState())
			if err != nil {
				var degraded *engine.DegradedError
				if c.name == "filtered" && errors.As(err, &degraded) && string(s.IncrementalState()) == string(seed) {
					return // Explicit incomplete coverage is acceptable; a clean checkpoint is not.
				}
				t.Fatalf("walk failed without preserving the degraded-coverage contract: %v", err)
			}
			if !found {
				t.Fatal("new in-scope diff was silently omitted")
			}
		})
	}
}

// TestOfflinePartialCloneSmallMissingBlob: a blob:none clone must not skip a
// needed in-scope blob — the filter provides no size floor.
func TestOfflinePartialCloneSmallMissingBlob(t *testing.T) {
	requireNativeGit(t)
	src, _ := buildRepo(t, []commitSpec{{files: map[string]string{"small.txt": "review_canary_small_secret\n"}, msg: "canary"}})
	dst := reviewClone(t, src, "blob:none")
	s := &Source{}
	mustInit(t, s, Config{Repo: dst})
	got, err := drain(t, s, 10*time.Second)
	t.Logf("chunks=%d err=%v state=%s", len(got), err, s.IncrementalState())
	if err == nil {
		t.Fatal("missing scannable blob must report incomplete coverage")
	}
}

// TestOfflinePromisorFalseMissingBlob: promisor=false is not permission to
// skip missing-blob errors.
func TestOfflinePromisorFalseMissingBlob(t *testing.T) {
	src, _ := buildRepo(t, []commitSpec{{files: map[string]string{"small.txt": "review_canary_small_secret\n"}, msg: "canary"}})
	hash := strings.TrimSpace(gitExec(t, src, "rev-parse", "HEAD:small.txt"))
	if err := os.Remove(filepath.Join(src, ".git", "objects", hash[:2], hash[2:])); err != nil {
		t.Fatal(err)
	}
	gitExec(t, src, "config", "remote.origin.promisor", "false")
	s := &Source{}
	mustInit(t, s, Config{Repo: src})
	got, err := drain(t, s, 10*time.Second)
	t.Logf("chunks=%d err=%v state=%s", len(got), err, s.IncrementalState())
	if err == nil {
		t.Fatal("promisor=false must not suppress missing-blob errors")
	}
}

// TestOfflinePartialCloneNotesStayOffline: a filtered-out notes blob must
// never be demand-fetched mid-walk.
func TestOfflinePartialCloneNotesStayOffline(t *testing.T) {
	requireNativeGit(t)
	src, _ := buildRepo(t, []commitSpec{{files: map[string]string{"small.txt": "ordinary content\n"}, msg: "initial"}})
	notePath := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(notePath, []byte(strings.Repeat("n", 51<<20)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	add := exec.Command("git", "-C", src, "-c", "user.name=Review", "-c", "user.email=review@example.com", "notes", "add", "-F", notePath, "HEAD")
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("notes add: %v %s", err, out)
	}
	list := exec.Command("git", "-C", src, "notes", "list", "HEAD")
	out, err := list.Output()
	if err != nil {
		t.Fatal(err)
	}
	noteHash := strings.Fields(string(out))[0]
	dst := reviewClone(t, src, "blob:limit=52428800")
	present := func() bool {
		cmd := exec.Command("git", "-C", dst, "cat-file", "-e", noteHash)
		cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1")
		return cmd.Run() == nil
	}
	if present() {
		t.Fatal("fixture note must be filtered out")
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: dst, IncludeCommitMetadata: true})
	got, err := drain(t, s, 30*time.Second)
	t.Logf("chunks=%d err=%v missing_note_fetched=%t", len(got), err, present())
	if present() {
		t.Fatal("history walk demand-fetched an omitted 51 MiB note")
	}
}

// TestOfflineRetainsIncludedText: fallback must apply the text policy, not
// the smaller artifact cap — an 11 MiB text blob retained locally is emitted.
func TestOfflineRetainsIncludedText(t *testing.T) {
	requireNativeGit(t)
	const marker = "review_included_text_canary"
	src, _ := buildRepo(t, []commitSpec{{files: map[string]string{
		"included.txt": marker + "\n" + strings.Repeat(strings.Repeat("x", 1023)+"\n", 11*1024),
		"filtered.bin": strings.Repeat("\x00", 51<<20),
	}, msg: "text plus oversized binary"}})
	dst := reviewClone(t, src, "blob:limit=52428800")
	hash := strings.TrimSpace(gitExec(t, src, "rev-parse", "HEAD:included.txt"))
	cmd := exec.Command("git", "-C", dst, "cat-file", "-e", hash)
	cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1")
	if err := cmd.Run(); err != nil {
		t.Fatal("11 MiB text must be locally present")
	}
	for _, c := range []struct{ name, dir string }{{"complete", src}, {"filtered", dst}} {
		t.Run(c.name, func(t *testing.T) {
			s := &Source{}
			mustInit(t, s, Config{Repo: c.dir})
			got, err := drain(t, s, 30*time.Second)
			found := false
			for _, chunk := range got {
				found = found || strings.Contains(string(chunk.Data), marker)
			}
			t.Logf("chunks=%d marker=%t err=%v state=%s", len(got), found, err, s.IncrementalState())
			// A missing blob that cannot be ruled out of scope must
			// degrade coverage — never checkpoint silently. Included
			// text must still be emitted alongside the degraded report.
			if err != nil {
				var degraded *engine.DegradedError
				if !errors.As(err, &degraded) {
					t.Fatal(err)
				}
			}
			if !found {
				t.Fatal("locally included text blob silently omitted")
			}
		})
	}
}

// TestOfflineEmptyCommit: an empty commit must not abort raw enumeration.
func TestOfflineEmptyCommit(t *testing.T) {
	requireNativeGit(t)
	src, _ := buildRepo(t, []commitSpec{{files: map[string]string{"a.txt": "first\n"}, msg: "base"}})
	gitExec(t, src, "commit", "--allow-empty", "-m", "empty")
	dst := reviewClone(t, src, "blob:limit=52428800")
	s := &Source{}
	mustInit(t, s, Config{Repo: dst})
	got, err := drain(t, s, 10*time.Second)
	t.Logf("chunks=%d err=%v", len(got), err)
	if err != nil {
		t.Fatal(err)
	}
}

// TestOfflineMergeWithOmittedParents: a merge whose parents' blobs were all
// filtered out still scans its retained result through the bounded fallback.
func TestOfflineMergeWithOmittedParents(t *testing.T) {
	requireNativeGit(t)
	src, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"a.txt": "base\n"}, msg: "root"},
		{files: map[string]string{"a.txt": strings.Repeat("L\n", (51<<20)/2)}, msg: "left"},
	})
	left := hashes[1]
	gitExec(t, src, "checkout", "--detach", hashes[0])
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte(strings.Repeat("R\n", (51<<20)/2)), 0o600); err != nil {
		t.Fatal(err)
	}
	gitExec(t, src, "commit", "-am", "right")
	right := strings.TrimSpace(gitExec(t, src, "rev-parse", "HEAD"))
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("review_merge_resolution_canary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitExec(t, src, "add", "a.txt")
	tree := strings.TrimSpace(gitExec(t, src, "write-tree"))
	merge := strings.TrimSpace(gitExec(t, src, "commit-tree", tree, "-p", left, "-p", right, "-m", "merge"))
	gitExec(t, src, "update-ref", "refs/heads/review", merge)
	gitExec(t, src, "symbolic-ref", "HEAD", "refs/heads/review")
	dst := reviewClone(t, src, "blob:limit=52428800")
	s := &Source{}
	mustInit(t, s, Config{Repo: dst})
	got, err := drain(t, s, 30*time.Second)
	found := false
	for _, chunk := range got {
		found = found || strings.Contains(string(chunk.Data), "review_merge_resolution_canary")
	}
	t.Logf("chunks=%d merge_canary=%t err=%v", len(got), found, err)
	// The parents' missing >50 MiB blobs may be in-scope text, so coverage
	// degrades rather than checkpointing; the merge resolution must still
	// emit its surviving blob.
	if err != nil {
		var degraded *engine.DegradedError
		if !errors.As(err, &degraded) {
			t.Fatal(err)
		}
	}
	if !found {
		t.Fatal("merge resolution content not scanned")
	}
}

// TestOfflineMissingNewWithRetainedBase: an M entry whose new blob is
// missing must degrade coverage even though the old blob is present —
// a readable base is no substitute for unread in-scope content.
func TestOfflineMissingNewWithRetainedBase(t *testing.T) {
	requireNativeGit(t)
	base := "ordinary base content\n"
	missing := strings.Repeat("z", 51<<20)
	src, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"a.txt": base}, msg: "base"},
		{files: map[string]string{"a.txt": missing}, msg: "bump"},
	})
	dst := reviewClone(t, src, "blob:limit=52428800")
	seed, err := json.Marshal(newIncrementalState([]plumbing.Hash{plumbing.NewHash(hashes[0])}))
	if err != nil {
		t.Fatal(err)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: dst})
	if err := s.SetIncrementalState(seed); err != nil {
		t.Fatal(err)
	}
	got, err := drain(t, s, 30*time.Second)
	t.Logf("chunks=%d err=%v state=%s", len(got), err, s.IncrementalState())
	if err == nil {
		t.Fatal("missing in-scope blob must not produce a clean walk")
	}
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) {
		t.Fatalf("want DegradedError, got %v", err)
	}
	if string(s.IncrementalState()) != string(seed) {
		t.Fatalf("checkpoint advanced past degraded coverage: %s", s.IncrementalState())
	}
}

// TestOfflineManyEmptyCommits: commits that produce no raw diff records
// must not deadlock the bounded commits queue — diff-tree runs with
// --always so every commit echoes its own ID, letting the consumer drain
// in lockstep with the producer.
func TestOfflineManyEmptyCommits(t *testing.T) {
	requireNativeGit(t)
	src, _ := buildRepo(t, []commitSpec{{files: map[string]string{"a.txt": "seed\n"}, msg: "seed"}})
	for i := 0; i < 1100; i++ {
		gitExec(t, src, "commit", "--allow-empty", "-m", "empty")
	}
	dst := reviewClone(t, src, "blob:limit=52428800")
	s := &Source{}
	mustInit(t, s, Config{Repo: dst})
	got, err := drain(t, s, 60*time.Second)
	t.Logf("chunks=%d err=%v", len(got), err)
	if err != nil {
		var degraded *engine.DegradedError
		if !errors.As(err, &degraded) {
			t.Fatal(err)
		}
	}
}

// TestOfflineConfigRemoteIsolation: remote.backup's promisor=false plus a
// partialclonefilter must not combine with remote.origin's promisor flag —
// per-remote association comes from the real Git config parser.
func TestOfflineConfigRemoteIsolation(t *testing.T) {
	requireNativeGit(t)
	src, _ := buildRepo(t, []commitSpec{{files: map[string]string{"a.txt": "review_canary_isolation\n"}, msg: "canary"}})
	dst := reviewClone(t, src, "blob:none")
	cfgPath := filepath.Join(dst, "config")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("[remote \"backup\"]\n\tpromisor = false\n\tpartialclonefilter = blob:none\n")...)
	if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: dst})
	got, err := drain(t, s, 30*time.Second)
	t.Logf("chunks=%d err=%v", len(got), err)
	if err == nil {
		t.Fatal("missing scannable blob must report incomplete coverage")
	}
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) {
		t.Fatalf("want DegradedError, got %v", err)
	}
}

// TestOfflineCloneSizeBoundaries: blob:limit=N omits blobs of size >= N —
// an N-1-byte blob survives the filter while exactly-N and N+1 do not. The
// missing adds may hold scannable text, so the walk degrades and retains
// the prior checkpoint.
func TestOfflineCloneSizeBoundaries(t *testing.T) {
	requireNativeGit(t)
	const marker = "boundary_marker_under_limit"
	under := strings.Repeat("f", (50<<20)-1-len(marker)-1) + marker + "\n" // 52428799 bytes
	exact := strings.Repeat("f", 50<<20)                                   // 52428800 bytes
	over := strings.Repeat("g", (50<<20)+1)                                // 52428801 bytes
	src, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"root.txt": "root\n"}, msg: "root"},
		{files: map[string]string{"under.bin": under}, msg: "under"},
		{files: map[string]string{"exact.bin": exact}, msg: "exact"},
		{files: map[string]string{"over.bin": over}, msg: "over"},
	})
	underHash := strings.TrimSpace(gitExec(t, src, "rev-parse", "HEAD~2:under.bin"))
	exactHash := strings.TrimSpace(gitExec(t, src, "rev-parse", "HEAD~1:exact.bin"))
	overHash := strings.TrimSpace(gitExec(t, src, "rev-parse", "HEAD:over.bin"))
	dst := reviewClone(t, src, "blob:limit=52428800")
	present := func(hash string) bool {
		cmd := exec.Command("git", "-C", dst, "cat-file", "-e", hash)
		cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1")
		return cmd.Run() == nil
	}
	if !present(underHash) {
		t.Fatal("N-1-byte blob must survive blob:limit=N")
	}
	if present(exactHash) {
		t.Fatal("exactly-N-byte blob must be omitted by blob:limit=N")
	}
	if present(overHash) {
		t.Fatal("N+1-byte blob must be omitted by blob:limit=N")
	}
	seed, err := json.Marshal(newIncrementalState([]plumbing.Hash{plumbing.NewHash(hashes[0])}))
	if err != nil {
		t.Fatal(err)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: dst})
	if err := s.SetIncrementalState(seed); err != nil {
		t.Fatal(err)
	}
	got, err := drain(t, s, 60*time.Second)
	found := false
	for _, chunk := range got {
		found = found || strings.Contains(string(chunk.Data), marker)
	}
	t.Logf("chunks=%d marker=%t err=%v", len(got), found, err)
	if !found {
		t.Fatal("surviving boundary blob was not scanned")
	}
	if err != nil {
		var degraded *engine.DegradedError
		if !errors.As(err, &degraded) {
			t.Fatalf("want DegradedError, got %v", err)
		}
	} else {
		t.Fatal("omitted in-scope blobs must degrade coverage")
	}
	if string(s.IncrementalState()) != string(seed) {
		t.Fatalf("checkpoint advanced past omitted blobs: %s", s.IncrementalState())
	}
}
