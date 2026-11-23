package gcs

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type fakeBucket struct {
	mu      sync.Mutex
	order   []string
	bodies  map[string][]byte
	fail    map[string]bool
	opened  []string
	listErr error
}

func (f *fakeBucket) List(_ context.Context, prefix string, fn func(objectInfo) error) error {
	for _, n := range f.order {
		b := f.bodies[n]
		if err := fn(objectInfo{Name: n, Generation: 1, State: objectIncrementalState{Generation: 1, Size: int64(len(b)), ETag: n}}); err != nil {
			return err
		}
	}
	return f.listErr
}

func (f *fakeBucket) Open(_ context.Context, name string, _ int64) (io.ReadCloser, error) {
	f.mu.Lock()
	f.opened = append(f.opened, name)
	f.mu.Unlock()
	if f.fail[name] {
		return nil, errors.New("backend says no: " + name)
	}
	return io.NopCloser(bytes.NewReader(f.bodies[name])), nil
}

func newTestSource(t *testing.T, b *fakeBucket) *Source {
	t.Helper()
	s := &Source{}
	if err := s.Init(t.Context(), "t", 0, 0, false, []byte(`{"bucket":"bkt"}`), 1); err != nil {
		t.Fatal(err)
	}
	s.openBucket = func(context.Context) (bucketAPI, func(), error) { return b, func() {}, nil }
	return s
}

func zipOf(t *testing.T, name, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create(name)
	_, _ = w.Write([]byte(body))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func drain(t *testing.T, s *Source) (map[string][]byte, error) {
	t.Helper()
	ch := make(chan *sources.Chunk, 32)
	err := s.Chunks(t.Context(), ch)
	close(ch)
	got := map[string][]byte{}
	for c := range ch {
		got[c.SourceMetadata.GCS.Object] = c.Data
	}
	return got, err
}

func TestChunksEmitsArchivesAndJoinsVolumes(t *testing.T) {
	whole := zipOf(t, "inner/secret.txt", "FIXTURE-GCS-JOINED")
	half := len(whole) / 2
	b := &fakeBucket{
		order: []string{"bk/data.zip.002", "bk/data.zip.001", "plain.zip", "notes.txt", "blob.bin"},
		bodies: map[string][]byte{
			"bk/data.zip.002": whole[half:],
			"bk/data.zip.001": whole[:half],
			"plain.zip":       zipOf(t, "a.txt", "FIXTURE-GCS-PLAIN"),
			"notes.txt":       []byte("hello"),
			"blob.bin":        {0, 1, 2, 3},
		},
	}
	s := newTestSource(t, b)
	got, err := drain(t, s)
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if want := []string{"bk/data.zip.001", "notes.txt", "plain.zip"}; len(keys) != 3 || keys[0] != want[0] || keys[1] != want[1] || keys[2] != want[2] {
		t.Fatalf("chunks %q", keys)
	}
	entries, err := archive.Walk("data.zip.001", got["bk/data.zip.001"], archive.Limits{})
	if err != nil || len(entries) != 1 || string(entries[0].Data) != "FIXTURE-GCS-JOINED" {
		t.Fatalf("joined walk: %v %v", entries, err)
	}
	state := s.IncrementalState()
	for _, k := range []string{"data.zip.001", "data.zip.002", "plain.zip", "blob.bin"} {
		if !bytes.Contains(state, []byte(k)) {
			t.Fatalf("%s missing from checkpoint: %s", k, state)
		}
	}
	s2 := newTestSource(t, b)
	if err := s2.SetIncrementalState(state); err != nil {
		t.Fatal(err)
	}
	b.opened = nil
	if _, err := drain(t, s2); err != nil {
		t.Fatal(err)
	}
	if len(b.opened) != 0 {
		t.Fatalf("unchanged objects re-downloaded: %q", b.opened)
	}
}

func TestChunksVolumeFailureIsCoverageGap(t *testing.T) {
	whole := zipOf(t, "s.txt", "FIXTURE")
	b := &fakeBucket{
		order:  []string{"d.zip.001", "d.zip.002"},
		bodies: map[string][]byte{"d.zip.001": whole[:10], "d.zip.002": whole[10:]},
		fail:   map[string]bool{"d.zip.002": true},
	}
	s := newTestSource(t, b)
	_, err := drain(t, s)
	var deg *engine.DegradedError
	if !errors.As(err, &deg) || deg.Total != 1 {
		t.Fatalf("want degraded error, got %v", err)
	}
	if bytes.Contains([]byte(deg.Error()), []byte("d.zip")) || bytes.Contains([]byte(deg.Error()), []byte("backend says")) {
		t.Fatalf("coverage diagnostics leak object names: %v", deg)
	}
	if bytes.Contains(s.IncrementalState(), []byte("d.zip.001")) {
		t.Fatalf("partially read set checkpointed: %s", s.IncrementalState())
	}
}

func TestChunksArchiveOverBudgetIsCoverageGap(t *testing.T) {
	big := zipOf(t, "x.txt", "FIXTURE")
	b := &fakeBucket{order: []string{"a.zip.001", "a.zip.002"}, bodies: map[string][]byte{"a.zip.001": big[:20], "a.zip.002": big[20:]}}
	s := newTestSource(t, b)
	s.maxSizeBytes = int64(len(big)) - 1 // each volume fits, the set does not
	got, err := drain(t, s)
	if err != nil {
		t.Fatal(err)
	}
	// Over-budget sets are not joined; each volume is scanned on its own
	// (the zip tail is binary and skipped).
	if _, ok := got["a.zip.001"]; !ok || len(got) != 1 || len(got["a.zip.001"]) != 20 {
		t.Fatalf("chunks %d", len(got))
	}
}

func TestChunksListErrorIsCoverageGap(t *testing.T) {
	b := &fakeBucket{listErr: errors.New("boom")}
	_, err := drain(t, newTestSource(t, b))
	var deg *engine.DegradedError
	if !errors.As(err, &deg) {
		t.Fatalf("want degraded error, got %v", err)
	}
}
