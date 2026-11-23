package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A commit costlier than one item is split by path into items that cover
// each of its paths exactly once; cheap commits are packed in order.
func TestCostWorkItemsSplitsHeavyCommit(t *testing.T) {
	heavy := make([]string, 40)
	for i := range heavy {
		heavy[i] = fmt.Sprintf("vendor/p%02d.go", i)
	}
	commits := []string{"c1", "heavy", "c2", "c3"}
	files := map[string][]string{"c1": {"a"}, "heavy": heavy, "c2": {"b"}, "c3": {"c"}}
	items := costWorkItems(commits, files, 4)
	seen := map[string]int{}
	var whole []string
	for _, it := range items {
		if len(it.paths) == 0 {
			whole = append(whole, it.commits...)
			continue
		}
		if len(it.commits) != 1 || it.commits[0] != "heavy" {
			t.Fatalf("path item for %v, want only the heavy commit", it.commits)
		}
		for _, p := range it.paths {
			seen[p]++
		}
	}
	if len(seen) != len(heavy) {
		t.Fatalf("split covers %d of %d paths", len(seen), len(heavy))
	}
	for p, n := range seen {
		if n != 1 {
			t.Fatalf("path %s rendered %d times", p, n)
		}
	}
	if strings.Join(whole, ",") != "c1,c2,c3" {
		t.Fatalf("whole commits = %v, want c1,c2,c3 in order", whole)
	}
	if items[0].cost < items[len(items)-1].cost {
		t.Fatalf("items not heaviest first: %+v", items)
	}
}

// Paths that cannot travel one per line on stdin keep their commit whole.
func TestCostWorkItemsKeepsUnsplittableCommitWhole(t *testing.T) {
	paths := []string{"ok.txt", "bad\nname.txt", "x", "y", "z"}
	items := costWorkItems([]string{"c"}, map[string][]string{"c": paths}, 4)
	if len(items) != 1 || len(items[0].paths) != 0 {
		t.Fatalf("items = %+v, want the commit whole", items)
	}
}

func TestParseChangedPaths(t *testing.T) {
	h1, h2 := strings.Repeat("a", 40), strings.Repeat("b", 40)
	out := "\x01" + h1 + "\x00\n:000000 100644 0 1 A\x00dir/with space.txt\x00:100644 100644 1 2 M\x00\"quoted\".txt\x00" +
		":120000 100644 2 3 T\x00link\x00\x01" + h2 + "\x00"
	got, err := parseChangedPaths([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got[h1], "|") != `dir/with space.txt|"quoted".txt|link` || len(got[h2]) != 0 {
		t.Fatalf("parsed %q", got)
	}
	if _, err := parseChangedPaths([]byte(":000000 100644 0 1 A\x00x\x00")); err == nil {
		t.Fatal("raw record outside a commit accepted")
	}
}

// A vendor-import commit with many paths, including names that need
// literal pathspecs, renders the same chunks split across workers as in
// the single native stream (#985).
func TestSplitHeavyCommitMatchesSingleStream(t *testing.T) {
	dir := buildShardRepo(t)
	for i := 0; i < 60; i++ {
		name := fmt.Sprintf("vendor/pkg%02d/file*%02d [x].go", i, i)
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(fmt.Sprintf("package p\nconst token = \"vendored-secret-%02d\"\n", i)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-qm", "vendor import")
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(filepath.Join(dir, "tail.txt"), []byte(strings.Repeat("t", i+1)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		gitRun(t, dir, "add", "-A")
		gitRun(t, dir, "commit", "-qm", "tail")
	}
	single := chunkKeys(t, dir, 1<<30)
	sharded := chunkKeys(t, dir, 1)
	if strings.Join(single, "\n") != strings.Join(sharded, "\n") {
		t.Fatalf("split chunks differ\nsingle:\n%s\nsharded:\n%s", strings.Join(single, "\n"), strings.Join(sharded, "\n"))
	}
	joined := strings.Join(sharded, "\n")
	for i := 0; i < 60; i++ {
		if !strings.Contains(joined, fmt.Sprintf("vendored-secret-%02d", i)) {
			t.Fatalf("missing vendored-secret-%02d", i)
		}
	}
}
