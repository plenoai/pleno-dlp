// Package volumeset groups multi-volume archive object names discovered
// while listing an object store (S3, GCS, ...) into join jobs for
// archive.JoinVolumes. Sources hold volume names back until listing ends
// so siblings spread across pages are grouped before dispatch.
package volumeset

import (
	"sort"

	"github.com/plenoai/pleno-dlp/pkg/archive"
)

// Member is one listed volume object.
type Member[T any] struct {
	Key  string
	Size int64
	Item T
}

// Job is either a linked set (Volumes holds volumes 2..n, Scheme is set)
// or a single object scanned on its own (Volumes empty).
type Job[T any] struct {
	Head    Member[T]
	Volumes []Member[T]
	Scheme  archive.VolumeScheme
}

// Sets collects volume names in listing order.
type Sets[T any] struct {
	sets  map[string]map[int]Member[T]
	ids   map[string]archive.VolumeID
	order []string
}

// New returns an empty collector.
func New[T any]() *Sets[T] {
	return &Sets[T]{sets: map[string]map[int]Member[T]{}, ids: map[string]archive.VolumeID{}}
}

// Add records key when it names an archive volume and reports whether it
// did; callers dispatch keys Add rejects as ordinary objects.
func (v *Sets[T]) Add(key string, size int64, item T) bool {
	id, ok := archive.ParseVolumeName(key)
	if !ok {
		return false
	}
	set := id.Sibling(1)
	if v.sets[set] == nil {
		v.sets[set] = map[int]Member[T]{}
		v.ids[set] = id
		v.order = append(v.order, set)
	}
	v.sets[set][id.Index] = Member[T]{Key: key, Size: size, Item: item}
	return true
}

// Jobs returns one job per linked set (volumes 1..n present, n >= 2, plus
// the terminal volume for schemes that have one, total within maxTotal) and
// a single-object job for every other volume key.
func (v *Sets[T]) Jobs(maxTotal int64) []Job[T] {
	var out []Job[T]
	for _, set := range v.order {
		members := v.sets[set]
		id := v.ids[set]
		var chain []Member[T]
		var total int64
		inChain := map[int]bool{}
		for i := 1; i <= archive.MaxVolumes; i++ {
			m, ok := members[i]
			if !ok || m.Key != id.Sibling(i) {
				break
			}
			total += m.Size
			chain = append(chain, m)
			inChain[i] = true
		}
		complete := true
		if term, ok := id.Terminal(); ok {
			m, present := members[0]
			complete = present && m.Key == term && len(chain) > 0
			if complete {
				total += m.Size
				chain = append(chain, m)
				inChain[0] = true
			}
		}
		linked := complete && len(chain) >= 2 && total <= maxTotal
		if linked {
			out = append(out, Job[T]{Head: chain[0], Volumes: chain[1:], Scheme: id.Scheme})
		}
		rest := make([]int, 0, len(members))
		for i := range members {
			if linked && inChain[i] {
				continue
			}
			rest = append(rest, i)
		}
		sort.Ints(rest)
		for _, i := range rest {
			out = append(out, Job[T]{Head: members[i]})
		}
	}
	return out
}

// All returns the head followed by the job's other volumes.
func (j Job[T]) All() []Member[T] {
	return append([]Member[T]{j.Head}, j.Volumes...)
}
