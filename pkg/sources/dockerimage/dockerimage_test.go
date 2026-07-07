package dockerimage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestSourceType(t *testing.T) {
	s := &Source{}
	if got := s.Type(); got != sources.SourceDockerImage {
		t.Fatalf("Type() = %v, want SourceDockerImage", got)
	}
}

func TestInit_missingImage(t *testing.T) {
	s := &Source{}
	if err := s.Init(context.Background(), "test", 1, 1, false, []byte(`{}`), 1); err == nil {
		t.Fatal("expected error for missing image, got nil")
	}
}

func TestInit_invalidGlob(t *testing.T) {
	s := &Source{}
	cfg, _ := json.Marshal(Config{Image: "alpine:3", Exclude: []string{"[invalid"}})
	if err := s.Init(context.Background(), "test", 1, 1, false, cfg, 1); err == nil {
		t.Fatal("expected error for invalid glob, got nil")
	}
}

func TestChunks_syntheticImage(t *testing.T) {
	// Build a minimal synthetic OCI image with one layer containing a text
	// file with a fake secret.
	img := buildTestImage(t, map[string]string{
		"/etc/config.env": "API_KEY=FAKESECRET12345\nUSER=admin\n",
		"/bin/binary":     "\x7fELF\x00\x00binary content",
	})

	s := &Source{
		name:     "test",
		sourceID: 1,
		cfg: Config{
			Image:        "test-image:latest",
			MaxLayerSize: defaultMaxLayerSize,
		},
	}

	ctx := context.Background()
	ch := make(chan *sources.Chunk, 64)

	go func() {
		defer close(ch)
		if err := s.chunksFromImage(ctx, img, "test-image:latest", "sha256:abc123", ch); err != nil {
			t.Errorf("Chunks: %v", err)
		}
	}()

	var chunks []*sources.Chunk
	for c := range ch {
		chunks = append(chunks, c)
	}

	if len(chunks) == 0 {
		t.Fatal("expected at least one chunk, got 0")
	}

	// Verify the text file chunk is present and the binary is absent.
	var found bool
	for _, c := range chunks {
		if c.SourceMetadata.DockerImage == nil {
			t.Error("chunk missing DockerImageMeta")
			continue
		}
		if c.SourceMetadata.DockerImage.File == "/etc/config.env" {
			found = true
			if !bytes.Contains(c.Data, []byte("FAKESECRET12345")) {
				t.Error("expected FAKESECRET12345 in config.env chunk")
			}
		}
		if c.SourceMetadata.DockerImage.File == "/bin/binary" {
			t.Error("binary file should have been skipped")
		}
	}
	if !found {
		t.Error("expected chunk for /etc/config.env, got none")
	}
}

func TestChunks_excludeGlob(t *testing.T) {
	img := buildTestImage(t, map[string]string{
		"/etc/secret.conf": "PASSWORD=hunter2\n",
		"/var/log/app.log": "INFO: started\n",
	})

	s := &Source{
		name:     "test",
		sourceID: 1,
		cfg: Config{
			Image:        "test-image:latest",
			MaxLayerSize: defaultMaxLayerSize,
			Exclude:      []string{"*.log"},
		},
	}

	ctx := context.Background()
	ch := make(chan *sources.Chunk, 64)
	go func() {
		defer close(ch)
		_ = s.chunksFromImage(ctx, img, "test-image:latest", "sha256:abc", ch)
	}()

	for c := range ch {
		if c.SourceMetadata.DockerImage != nil && c.SourceMetadata.DockerImage.File == "/var/log/app.log" {
			t.Error("excluded *.log file should not produce a chunk")
		}
	}
}

func TestIsBinary(t *testing.T) {
	if !isBinary([]byte("\x7fELF\x00rest")) {
		t.Error("ELF should be binary")
	}
	if isBinary([]byte("hello world\nno nulls here\n")) {
		t.Error("text should not be binary")
	}
}

// buildTestImage constructs a synthetic OCI image with one layer containing
// the given path→content entries.
func buildTestImage(t *testing.T, files map[string]string) v1.Image {
	t.Helper()
	return buildTestImageLayers(t, files)
}

// buildTestImageLayers constructs a synthetic OCI image with one layer per
// argument. Tar headers omit timestamps, so a layer's uncompressed content
// (and therefore its DiffID) is a deterministic function of its file set —
// two calls with the same files produce the same DiffID.
func buildTestImageLayers(t *testing.T, layerFiles ...map[string]string) v1.Image {
	t.Helper()

	img := empty.Image
	for _, files := range layerFiles {
		layer := buildTestLayer(t, files)
		var err error
		img, err = mutate.AppendLayers(img, layer)
		if err != nil {
			t.Fatalf("append layer: %v", err)
		}
	}
	return img
}

func buildTestLayer(t *testing.T, files map[string]string) v1.Layer {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for path, content := range files {
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     path,
			Size:     int64(len(content)),
			Mode:     0644,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar header %s: %v", path, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write %s: %v", path, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	data := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		t.Fatalf("create layer: %v", err)
	}
	return layer
}

func chunkFiles(chunks []*sources.Chunk) map[string]bool {
	files := map[string]bool{}
	for _, c := range chunks {
		if c.SourceMetadata.DockerImage != nil && c.SourceMetadata.DockerImage.Layer != "config" {
			files[c.SourceMetadata.DockerImage.File] = true
		}
	}
	return files
}

func collectChunks(t *testing.T, s *Source, img v1.Image, digest string) []*sources.Chunk {
	t.Helper()
	ctx := context.Background()
	ch := make(chan *sources.Chunk, 64)
	go func() {
		defer close(ch)
		if err := s.chunksFromImage(ctx, img, "test-image:latest", digest, ch); err != nil {
			t.Errorf("chunksFromImage: %v", err)
		}
	}()
	var chunks []*sources.Chunk
	for c := range ch {
		chunks = append(chunks, c)
	}
	return chunks
}

// TestIncremental_firstScanCoversAllLayers verifies (a): a source with no
// previous state scans every layer.
func TestIncremental_firstScanCoversAllLayers(t *testing.T) {
	img := buildTestImageLayers(t,
		map[string]string{"/a.txt": "AAA=1\n"},
		map[string]string{"/b.txt": "BBB=2\n"},
	)
	s := &Source{name: "test", sourceID: 1, cfg: Config{Image: "test-image:latest", MaxLayerSize: defaultMaxLayerSize}}

	files := chunkFiles(collectChunks(t, s, img, "sha256:img1"))
	if !files["/a.txt"] || !files["/b.txt"] {
		t.Fatalf("first scan must cover all layers, got %v", files)
	}
	if len(s.nextState.Layers) != 2 {
		t.Fatalf("nextState should record 2 layers, got %d", len(s.nextState.Layers))
	}
}

// TestIncremental_rescanSkipsKnownLayers verifies (b): re-scanning the same
// image with the previous scan's state skips every layer (content-addressed
// digests are unchanged), while still recording them in the new state.
func TestIncremental_rescanSkipsKnownLayers(t *testing.T) {
	img := buildTestImageLayers(t,
		map[string]string{"/a.txt": "AAA=1\n"},
		map[string]string{"/b.txt": "BBB=2\n"},
	)

	first := &Source{name: "test", sourceID: 1, cfg: Config{Image: "test-image:latest", MaxLayerSize: defaultMaxLayerSize}}
	collectChunks(t, first, img, "sha256:img1")
	baseline := first.IncrementalState()
	if len(baseline) == 0 {
		t.Fatal("expected non-empty incremental state after first scan")
	}

	second := &Source{name: "test", sourceID: 1, cfg: Config{Image: "test-image:latest", MaxLayerSize: defaultMaxLayerSize}}
	if err := second.SetIncrementalState(baseline); err != nil {
		t.Fatalf("SetIncrementalState: %v", err)
	}
	files := chunkFiles(collectChunks(t, second, img, "sha256:img1"))
	if len(files) != 0 {
		t.Fatalf("rescan of unchanged image should skip every layer, got chunks for %v", files)
	}
	if len(second.nextState.Layers) != 2 {
		t.Fatalf("nextState should still record 2 layers, got %d", len(second.nextState.Layers))
	}
}

// TestIncremental_newLayerOnlyScansTheAddition verifies (c): adding a layer
// to a previously-scanned image scans only the new layer.
func TestIncremental_newLayerOnlyScansTheAddition(t *testing.T) {
	layerA := map[string]string{"/a.txt": "AAA=1\n"}
	layerB := map[string]string{"/b.txt": "BBB=2\n"}
	layerC := map[string]string{"/c.txt": "CCC=3\n"}

	baselineImg := buildTestImageLayers(t, layerA, layerB)
	first := &Source{name: "test", sourceID: 1, cfg: Config{Image: "test-image:latest", MaxLayerSize: defaultMaxLayerSize}}
	collectChunks(t, first, baselineImg, "sha256:img1")
	baseline := first.IncrementalState()

	extendedImg := buildTestImageLayers(t, layerA, layerB, layerC)
	second := &Source{name: "test", sourceID: 1, cfg: Config{Image: "test-image:latest", MaxLayerSize: defaultMaxLayerSize}}
	if err := second.SetIncrementalState(baseline); err != nil {
		t.Fatalf("SetIncrementalState: %v", err)
	}
	files := chunkFiles(collectChunks(t, second, extendedImg, "sha256:img2"))
	if len(files) != 1 || !files["/c.txt"] {
		t.Fatalf("expected only the new layer's file /c.txt, got %v", files)
	}
	if len(second.nextState.Layers) != 3 {
		t.Fatalf("nextState should record all 3 layers, got %d", len(second.nextState.Layers))
	}
}

func TestIncrementalState_roundTrip(t *testing.T) {
	s := &Source{nextState: &incrementalState{Version: 1, Layers: map[string]bool{"sha256:abc": true}}}
	raw := s.IncrementalState()
	if len(raw) == 0 {
		t.Fatal("IncrementalState must not be empty")
	}
	var decoded incrementalState
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode IncrementalState: %v", err)
	}
	if !decoded.Layers["sha256:abc"] {
		t.Fatalf("decoded state = %#v, want layer marked scanned", decoded)
	}
}

func TestResourceFingerprint_stableForUnchangedImage(t *testing.T) {
	img := buildTestImageLayers(t, map[string]string{"/a.txt": "AAA=1\n"})
	s := &Source{cfg: Config{Image: "test-image:latest", MaxLayerSize: defaultMaxLayerSize}}

	fp1, err := s.fingerprintFromImage(img, "test-image:latest", "sha256:img1")
	if err != nil {
		t.Fatalf("fingerprintFromImage: %v", err)
	}
	fp2, err := s.fingerprintFromImage(img, "test-image:latest", "sha256:img1")
	if err != nil {
		t.Fatalf("fingerprintFromImage: %v", err)
	}
	if fp1 != fp2 {
		t.Fatalf("fingerprint must be stable for an unchanged image: %s != %s", fp1, fp2)
	}
}

func TestResourceFingerprint_changesWithNewLayer(t *testing.T) {
	layerA := map[string]string{"/a.txt": "AAA=1\n"}
	layerB := map[string]string{"/b.txt": "BBB=2\n"}

	s := &Source{cfg: Config{Image: "test-image:latest", MaxLayerSize: defaultMaxLayerSize}}
	fp1, err := s.fingerprintFromImage(buildTestImageLayers(t, layerA), "test-image:latest", "sha256:img1")
	if err != nil {
		t.Fatalf("fingerprintFromImage: %v", err)
	}
	fp2, err := s.fingerprintFromImage(buildTestImageLayers(t, layerA, layerB), "test-image:latest", "sha256:img2")
	if err != nil {
		t.Fatalf("fingerprintFromImage: %v", err)
	}
	if fp1 == fp2 {
		t.Fatal("fingerprint must change when a layer is added")
	}
}

func TestIncrementalState_empty(t *testing.T) {
	s := &Source{}
	if err := s.SetIncrementalState(nil); err != nil {
		t.Fatalf("SetIncrementalState(nil): %v", err)
	}
	if s.hasPreviousState {
		t.Fatal("should not have previous state")
	}
	if raw := s.IncrementalState(); raw != nil {
		t.Fatalf("IncrementalState should be nil before Chunks, got %s", raw)
	}
}
