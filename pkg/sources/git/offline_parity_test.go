package git

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const offlineParityBlobFilter = "blob:limit=52428800"

type offlineParityChunk struct {
	SourceID   int64
	SourceType sources.SourceType
	SourceName string
	Data       string
	Git        sources.GitMeta
}

func completeMirror(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "mirror")
	gitExec(t, t.TempDir(), "clone", "-q", "--mirror", "--", "file://"+filepath.ToSlash(src), dst)
	return dst
}

func offlineParityChunks(t *testing.T, repo string, chunks []*sources.Chunk) []offlineParityChunk {
	t.Helper()
	got := make([]offlineParityChunk, 0, len(chunks))
	for _, chunk := range chunks {
		meta := chunk.SourceMetadata.Git
		if meta == nil {
			t.Fatal("chunk is missing Git metadata")
		}
		if meta.Repository != repo {
			t.Fatalf("Repository metadata = %q, want %q", meta.Repository, repo)
		}
		copy := *meta
		// Repository is intentionally clone-local; compare every other field.
		copy.Repository = ""
		got = append(got, offlineParityChunk{
			SourceID: chunk.SourceID, SourceType: chunk.SourceType,
			SourceName: chunk.SourceName, Data: string(chunk.Data), Git: copy,
		})
	}
	return got
}

func requireLocalGitObject(t *testing.T, repo, hash string) {
	t.Helper()
	cmd := exec.Command("git", "-C", repo, "cat-file", "-e", hash)
	cmd.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("object %s is not locally available in %s: %v\n%s", hash, repo, err, out)
	}
}

func TestChunks_OfflineFilteredParity_AllBranchesIncrementalMetadata(t *testing.T) {
	requireNativeGit(t)
	baseTime := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	src, hashes := buildRepo(t, []commitSpec{{
		files: map[string]string{"shared.txt": "shared root\n"}, msg: "shared root",
		when: baseTime,
	}})
	root := hashes[0]
	repo, err := gogit.PlainOpen(src)
	if err != nil {
		t.Fatal(err)
	}
	defaultHead, err := repo.Head()
	if err != nil {
		t.Fatal(err)
	}
	defaultBranch := defaultHead.Name()
	checkoutNewBranch(t, repo, "feature")
	featureHead := commitOn(t, repo, map[string]string{"feature.txt": "feature tip\n"}, "feature tip", baseTime.Add(time.Minute))
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := wt.Checkout(&gogit.CheckoutOptions{Branch: defaultBranch}); err != nil {
		t.Fatalf("checkout default branch: %v", err)
	}
	mainHead := commitOn(t, repo, map[string]string{"main.txt": "main tip\n"}, "main tip", baseTime.Add(2*time.Minute))
	const rootNote = "offline parity root note"
	gitExec(t, src, "notes", "add", "-m", rootNote, root)
	rootBlob := strings.Fields(gitExec(t, src, "rev-parse", root+":shared.txt"))[0]
	featureBlob := strings.Fields(gitExec(t, src, "rev-parse", featureHead+":feature.txt"))[0]
	mainBlob := strings.Fields(gitExec(t, src, "rev-parse", mainHead+":main.txt"))[0]
	rootNoteBlob := strings.Fields(gitExec(t, src, "notes", "list", root))[0]

	complete := completeMirror(t, src)
	filtered := reviewClone(t, src, offlineParityBlobFilter)
	for _, hash := range []string{rootBlob, featureBlob, mainBlob, rootNoteBlob} {
		requireLocalGitObject(t, filtered, hash)
	}

	newSource := func(clone string) *Source {
		t.Helper()
		s := &Source{}
		mustInit(t, s, Config{Repo: clone, AllBranches: true, IncludeCommitMetadata: true})
		return s
	}

	completeFirst, filteredFirst := newSource(complete), newSource(filtered)
	completeChunks, err := drain(t, completeFirst, 30*time.Second)
	if err != nil {
		t.Fatalf("complete mirror initial scan: %v", err)
	}
	filteredChunks, err := drain(t, filteredFirst, 30*time.Second)
	if err != nil {
		t.Fatalf("filtered mirror initial scan: %v", err)
	}
	if completeFirst.promisorFiltered {
		t.Fatal("complete mirror was misclassified as promisor-filtered")
	}
	if !filteredFirst.promisorFiltered {
		t.Fatal("filtered mirror did not exercise the offline walker")
	}
	completeParity := offlineParityChunks(t, complete, completeChunks)
	filteredParity := offlineParityChunks(t, filtered, filteredChunks)
	if !reflect.DeepEqual(completeParity, filteredParity) {
		t.Fatalf("initial ordered chunks differ between complete and filtered mirrors:\ncomplete=%+v\nfiltered=%+v", completeParity, filteredParity)
	}
	if len(completeChunks) != 6 {
		t.Fatalf("initial chunks=%d, want 3 file chunks plus 3 metadata chunks", len(completeChunks))
	}
	files := map[string]int{}
	metadata := map[string]int{}
	for _, chunk := range completeChunks {
		meta := chunk.SourceMetadata.Git
		if strings.HasPrefix(meta.File, "commit:metadata/") {
			metadata[meta.Commit]++
		} else {
			files[meta.File]++
		}
	}
	for _, name := range []string{"shared.txt", "feature.txt", "main.txt"} {
		if files[name] != 1 {
			t.Fatalf("initial %s chunks=%d, want one; files=%v", name, files[name], files)
		}
	}
	for _, hash := range []string{root, featureHead, mainHead} {
		if metadata[hash] != 1 {
			t.Fatalf("metadata for %s emitted %d times, want once; metadata=%v", hash, metadata[hash], metadata)
		}
	}
	if !strings.Contains(completeParity[3].Data+completeParity[4].Data+completeParity[5].Data, rootNote) {
		t.Fatal("root commit note missing from commit metadata")
	}
	if completeParity[0].Git.Commit != root {
		t.Fatalf("oldest file chunk is for %s, want shared root %s", completeParity[0].Git.Commit, root)
	}
	oldState := completeFirst.IncrementalState()
	if len(oldState) == 0 || string(filteredFirst.IncrementalState()) != string(oldState) {
		t.Fatalf("initial incremental states differ or are empty: complete=%s filtered=%s", oldState, filteredFirst.IncrementalState())
	}
	var previous incrementalState
	if err := json.Unmarshal(oldState, &previous); err != nil {
		t.Fatal(err)
	}
	if len(previous.Heads) != 2 || !containsString(previous.Heads, mainHead) || !containsString(previous.Heads, featureHead) {
		t.Fatalf("initial state did not record both branch heads: %+v", previous)
	}

	if err := wt.Checkout(&gogit.CheckoutOptions{Branch: defaultBranch}); err != nil {
		t.Fatalf("checkout default branch for update: %v", err)
	}
	mainNext := commitOn(t, repo, map[string]string{"main-next.txt": "main next\n"}, "main next", baseTime.Add(3*time.Minute))
	if err := wt.Checkout(&gogit.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("feature")}); err != nil {
		t.Fatalf("checkout feature branch for update: %v", err)
	}
	featureNext := commitOn(t, repo, map[string]string{"feature-next.txt": "feature next\n"}, "feature next", baseTime.Add(4*time.Minute))
	for _, clone := range []string{complete, filtered} {
		gitExec(t, clone, "fetch", "--prune", "origin")
	}
	for _, spec := range []struct{ path, expression string }{
		{"main-next.txt", mainNext + ":main-next.txt"},
		{"feature-next.txt", featureNext + ":feature-next.txt"},
	} {
		hash := strings.Fields(gitExec(t, src, "rev-parse", spec.expression))[0]
		requireLocalGitObject(t, filtered, hash)
	}

	completeSecond, filteredSecond := newSource(complete), newSource(filtered)
	for _, s := range []*Source{completeSecond, filteredSecond} {
		if err := s.SetIncrementalState(oldState); err != nil {
			t.Fatal(err)
		}
	}
	completeNextChunks, err := drain(t, completeSecond, 30*time.Second)
	if err != nil {
		t.Fatalf("complete mirror incremental scan: %v", err)
	}
	filteredNextChunks, err := drain(t, filteredSecond, 30*time.Second)
	if err != nil {
		t.Fatalf("filtered mirror incremental scan: %v", err)
	}
	completeNextParity := offlineParityChunks(t, complete, completeNextChunks)
	filteredNextParity := offlineParityChunks(t, filtered, filteredNextChunks)
	if !reflect.DeepEqual(completeNextParity, filteredNextParity) {
		t.Fatalf("incremental ordered chunks differ between complete and filtered mirrors:\ncomplete=%+v\nfiltered=%+v", completeNextParity, filteredNextParity)
	}
	if len(completeNextChunks) != 4 {
		t.Fatalf("incremental chunks=%d, want two new file chunks plus two metadata chunks", len(completeNextChunks))
	}
	newCommits := map[string]bool{mainNext: true, featureNext: true}
	newFiles := map[string]int{}
	for _, chunk := range completeNextChunks {
		meta := chunk.SourceMetadata.Git
		if !newCommits[meta.Commit] {
			t.Fatalf("incremental scan re-emitted old commit %s (%s)", meta.Commit, meta.File)
		}
		if strings.HasPrefix(meta.File, "commit:metadata/") {
			continue
		}
		newFiles[meta.File]++
	}
	for _, name := range []string{"main-next.txt", "feature-next.txt"} {
		if newFiles[name] != 1 {
			t.Fatalf("incremental %s chunks=%d, want one; files=%v", name, newFiles[name], newFiles)
		}
	}
	if string(completeSecond.IncrementalState()) == string(oldState) || string(completeSecond.IncrementalState()) != string(filteredSecond.IncrementalState()) {
		t.Fatalf("updated states are unchanged or differ: old=%s complete=%s filtered=%s", oldState, completeSecond.IncrementalState(), filteredSecond.IncrementalState())
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
