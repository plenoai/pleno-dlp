package s3

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"sort"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestChunksJoinsSplitVolumes(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("inner/secret.txt")
	_, _ = w.Write([]byte("FIXTURE-S3-JOINED"))
	_ = zw.Close()
	whole := buf.Bytes()
	half := len(whole) / 2
	bodies := map[string][]byte{
		"backups/data.zip.002": whole[half:], // listed before volume 1
		"backups/data.zip.001": whole[:half],
		"solo.zip.001":         whole, // no sibling: scanned as itself
	}
	var objs []types.Object
	for _, k := range []string{"backups/data.zip.002", "backups/data.zip.001", "solo.zip.001"} {
		objs = append(objs, object(k, int64(len(bodies[k]))))
	}
	client := &fakeS3Client{objects: objs, get: func(_ context.Context, key string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(bodies[key])), nil
	}}
	s := testSource(client, 2, defaultMaxObjectSize)
	ch := make(chan *sources.Chunk, 8)
	if err := s.Chunks(t.Context(), ch); err != nil {
		t.Fatal(err)
	}
	close(ch)
	var keys []string
	for c := range ch {
		keys = append(keys, c.SourceMetadata.S3.Key)
		if c.SourceMetadata.S3.Key == "backups/data.zip.001" {
			entries, err := archive.Walk("data.zip.001", c.Data, archive.Limits{})
			if err != nil || len(entries) != 1 || string(entries[0].Data) != "FIXTURE-S3-JOINED" {
				t.Fatalf("joined walk: %v %v", entries, err)
			}
		}
	}
	sort.Strings(keys)
	if len(keys) != 2 || keys[0] != "backups/data.zip.001" || keys[1] != "solo.zip.001" {
		t.Fatalf("chunks %q", keys)
	}
	state := s.IncrementalState()
	if !bytes.Contains(state, []byte("data.zip.002")) {
		t.Fatalf("continuation volume missing from checkpoint: %s", state)
	}
	// A second run with the same objects downloads nothing.
	s2 := testSource(client, 2, defaultMaxObjectSize)
	if err := s2.SetIncrementalState(state); err != nil {
		t.Fatal(err)
	}
	before := len(client.calls())
	ch2 := make(chan *sources.Chunk, 8)
	if err := s2.Chunks(t.Context(), ch2); err != nil {
		t.Fatal(err)
	}
	if got := len(client.calls()) - before; got != 0 {
		t.Fatalf("unchanged volumes re-downloaded %d objects", got)
	}
}
