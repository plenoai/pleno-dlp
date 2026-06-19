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

// chunksFromImage is a test helper that runs the scan against an already-loaded
// v1.Image without going through registry/daemon pull.
func (s *Source) chunksFromImage(ctx context.Context, img v1.Image, ref, digest string, ch chan<- *sources.Chunk) error {
	if err := s.emitConfig(ctx, img, ref, digest, ch); err != nil {
		return err
	}
	layers, err := img.Layers()
	if err != nil {
		return err
	}
	for _, layer := range layers {
		if err := s.emitLayer(ctx, layer, ref, digest, ch); err != nil {
			return err
		}
	}
	return nil
}

// buildTestImage constructs a synthetic OCI image with one layer containing
// the given path→content entries.
func buildTestImage(t *testing.T, files map[string]string) v1.Image {
	t.Helper()

	// Build a tar of the files.
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
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	return img
}
