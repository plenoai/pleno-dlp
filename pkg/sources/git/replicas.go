package git

import (
	"encoding/hex"
	"strings"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// diffReplicaLimit bounds the identical-diff index. Past it new diffs are
// simply scanned (never skipped), so the cap trades speed, not coverage.
const diffReplicaLimit = 2 << 20

// diffKey identifies one rendered file diff: with fixed patch options the
// same path, pre-image, and post-image always render the same lines.
type diffKey struct {
	pre, post [20]byte
	path      string
}

// diffReplicaRegistry maps every file diff scanned in one walk to the
// replica set its chunks carry. Shared by the parallel history shards.
type diffReplicaRegistry struct {
	mu sync.Mutex
	m  map[diffKey]*sources.DiffReplicas
}

func newDiffReplicaRegistry(enabled bool) *diffReplicaRegistry {
	if !enabled {
		return nil
	}
	return &diffReplicaRegistry{m: make(map[diffKey]*sources.DiffReplicas)}
}

// claim registers the diff for commit c. The first caller scans it and gets
// (set, false); later callers are recorded as replicas and get (nil, true),
// meaning the diff must be skipped. A nil registry or an unusable key
// (missing ids) always scans.
func (r *diffReplicaRegistry) claim(path, indexLine string, c *nativeCommit) (*sources.DiffReplicas, bool) {
	if r == nil || c == nil || path == "" {
		return nil, false
	}
	key, ok := parseDiffKey(path, indexLine)
	if !ok {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if set, exists := r.m[key]; exists {
		set.Add(sources.DiffReplica{Commit: c.hash, Email: c.email, Author: c.author, AuthoredDate: c.authoredDate, Message: c.message, Ordinal: c.ordinal})
		return nil, true
	}
	if len(r.m) >= diffReplicaLimit {
		return nil, false
	}
	set := &sources.DiffReplicas{}
	r.m[key] = set
	return set, false
}

// parseDiffKey reads "index <pre>..<post>[ <mode>]" with full 40-hex ids.
func parseDiffKey(path, line string) (diffKey, bool) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "index "))
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		rest = rest[:sp]
	}
	pre, post, ok := strings.Cut(rest, "..")
	if !ok || len(pre) != 40 || len(post) != 40 {
		return diffKey{}, false
	}
	k := diffKey{path: path}
	if _, err := hex.Decode(k.pre[:], []byte(pre)); err != nil {
		return diffKey{}, false
	}
	if _, err := hex.Decode(k.post[:], []byte(post)); err != nil {
		return diffKey{}, false
	}
	return k, true
}
