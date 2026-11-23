package git

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// buildDeltaRepo creates a packed repository whose blobs form long delta
// chains (one file rewritten across many commits) and returns its objects
// directory and every blob id.
func buildDeltaRepo(t *testing.T) (dir string, blobs []string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir = t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main")
	var body strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&body, "line %d of a file that keeps growing and changing\n", i)
	}
	base := body.String()
	for c := 0; c < 60; c++ {
		content := strings.Replace(base, fmt.Sprintf("line %d ", c*5), fmt.Sprintf("edited %d ", c), 1) +
			strings.Repeat(fmt.Sprintf("tail %d\n", c), c)
		base = content
		if err := os.WriteFile(filepath.Join(dir, "big.txt"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("small-%d.txt", c%7)), []byte(strings.Repeat("s", c+1)+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		gitRun(t, dir, "add", "-A")
		gitRun(t, dir, "commit", "-qm", fmt.Sprintf("c%d", c))
	}
	gitRun(t, dir, "repack", "-adq", "--depth=50", "--window=250")
	out, err := exec.Command("git", "-C", dir, "verify-pack", "-v", filepath.Join(dir, ".git", "objects", "pack", mustGlobOne(t, filepath.Join(dir, ".git", "objects", "pack", "*.idx")))).Output()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("chain length = 2")) {
		t.Fatalf("fixture has no delta chains:\n%s", out)
	}
	list, err := exec.Command("git", "-C", dir, "cat-file", "--batch-all-objects", "--batch-check=%(objecttype) %(objectname)").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(list)), "\n") {
		if typ, oid, ok := strings.Cut(line, " "); ok && typ == "blob" {
			blobs = append(blobs, oid)
		}
	}
	return dir, blobs
}

func mustGlobOne(t *testing.T, pattern string) string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	if err != nil || len(m) != 1 {
		t.Fatalf("glob %s: %v %v", pattern, m, err)
	}
	return filepath.Base(m[0])
}

// TestObjectDBMatchesGit reads every blob of a delta-heavy pack through the
// shared object store, concurrently and with caches from none to ample, and
// pins each against git cat-file.
func TestObjectDBMatchesGit(t *testing.T) {
	dir, blobs := buildDeltaRepo(t)
	want := make(map[string][]byte, len(blobs))
	for _, oid := range blobs {
		out, err := exec.Command("git", "-C", dir, "cat-file", "blob", oid).Output()
		if err != nil {
			t.Fatal(err)
		}
		want[oid] = out
	}
	for _, cache := range []int64{0, 64 << 10, 64 << 20} {
		db, err := openObjectDB(filepath.Join(dir, ".git", "objects"), cache)
		if err != nil || db == nil {
			t.Fatalf("openObjectDB: %v %v", db, err)
		}
		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for round := 0; round < 3; round++ {
					for i := range blobs {
						oid := blobs[(i*(g+1)+round)%len(blobs)]
						ref, err := db.readBlobRef(oid, 1<<30)
						if err != nil {
							t.Errorf("cache %d: %s: %v", cache, oid, err)
							return
						}
						if !bytes.Equal(ref.data, want[oid]) {
							t.Errorf("cache %d: %s content differs", cache, oid)
						}
						ref.release(db)
					}
				}
			}()
		}
		wg.Wait()
		if _, err := db.readBlobRef(blobs[0], 1); err == nil && len(want[blobs[0]]) > 1 {
			t.Errorf("cache %d: limit not enforced", cache)
		}
		if _, err := db.readBlobRef(strings.Repeat("0", 40), 1<<30); err != errODBMiss {
			t.Errorf("missing object: %v", err)
		}
		db.close()
	}
}

// TestODBCacheRefcount pins that an evicted entry still being read is not
// recycled until its last reader releases it, and that LRU evicts the
// least recently used entry.
func TestODBCacheRefcount(t *testing.T) {
	db := &objectDB{}
	db.cache = newODBCache(db, 64*4096) // 4 KiB per stripe
	mk := func(fill byte) *odbBuf {
		b := db.bufs.get(1024)
		b.data = append(b.data[:0], bytes.Repeat([]byte{fill}, 1024)...)
		return b
	}
	// Entries of different packs at one offset share a stripe.
	a := mk('a')
	db.cache.put(0, 0, odbObjBlob, a)
	a.release(db) // cache now holds the only reference
	_, held, ok := db.cache.get(0, 0)
	if !ok || held != a {
		t.Fatal("cached entry missing")
	}
	// Fill the stripe until a is evicted while held.
	for i := int64(1); i <= 4; i++ {
		b := mk(byte('a' + i))
		db.cache.put(int(i), 0, odbObjBlob, b)
		b.release(db)
	}
	if _, _, ok := db.cache.get(0, 0); ok {
		t.Fatal("least recently used entry not evicted")
	}
	if got := held.refs.Load(); got != 1 {
		t.Fatalf("held reference count = %d, want 1", got)
	}
	// A recycled buffer would be handed out (and overwritten) here.
	c := db.bufs.get(1024)
	if &c.data[:1][0] == &held.data[:1][0] {
		t.Fatal("buffer recycled while still referenced")
	}
	if !bytes.Equal(held.data, bytes.Repeat([]byte{'a'}, 1024)) {
		t.Fatal("held data changed after eviction")
	}
	held.release(db)
	if d := db.bufs.get(1024); &d.data[:1][0] != &held.data[:1][0] {
		t.Fatal("released buffer not recycled")
	}
}
