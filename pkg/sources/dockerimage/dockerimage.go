// Package dockerimage scans OCI/Docker image layers and the image config blob
// for secrets. It supports both registry pull (no daemon required) and local
// Docker daemon images via the from_daemon config flag.
//
// What is scanned:
//   - Image config blob: ENV, Labels, Cmd, Entrypoint (rendered as KEY=VALUE lines)
//   - Every regular file in every layer whose content is not binary
//
// Layer order follows the OCI spec (base → top); files overwritten in later
// layers are scanned in each layer independently (union-FS view is not
// reconstructed — this is intentional: a secret deleted in a later layer is
// still present in the earlier one).
package dockerimage

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	defaultMaxLayerSize int64 = 500 * 1024 * 1024 // 500 MiB per layer
	binarySniffLen            = 512
)

func init() {
	sources.Register(sources.SourceDockerImage, func() sources.Source { return &Source{} })
}

// Config is the JSON configuration for the docker-image source.
type Config struct {
	// Image is the image reference, e.g. "docker.io/library/alpine:3.20" or
	// "sha256:<digest>". Required.
	Image string `json:"image"`

	// Platform selects a manifest list entry, e.g. "linux/amd64".
	// Ignored for single-arch images.
	Platform string `json:"platform,omitempty"`

	// FromDaemon, when true, loads the image from the local Docker daemon
	// instead of pulling from a registry.
	FromDaemon bool `json:"from_daemon,omitempty"`

	// Username / Password for registry authentication.
	// When empty, keychain auth (docker config, credential helpers) is used.
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// MaxLayerSize caps how many bytes are read per layer (default 500 MiB).
	MaxLayerSize int64 `json:"max_layer_size,omitempty"`

	// Include / Exclude are glob patterns matched against file paths inside
	// each layer. Exclude takes priority over Include.
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// Source implements sources.Source for Docker/OCI images.
type Source struct {
	name        string
	jobID       int64
	sourceID    int64
	verify      bool
	concurrency int
	cfg         Config
}

func (s *Source) Type() sources.SourceType { return sources.SourceDockerImage }

func (s *Source) Init(_ context.Context, name string, jobID, sourceID int64, verify bool, cfgJSON []byte, concurrency int) error {
	var cfg Config
	if len(cfgJSON) > 0 {
		if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
			return fmt.Errorf("docker-image: invalid config json: %w", err)
		}
	}
	if cfg.Image == "" {
		return errors.New("docker-image: config.image must be set")
	}
	if cfg.MaxLayerSize <= 0 {
		cfg.MaxLayerSize = defaultMaxLayerSize
	}
	for _, p := range append(append([]string{}, cfg.Include...), cfg.Exclude...) {
		if _, err := filepath.Match(p, ""); err != nil {
			return fmt.Errorf("docker-image: invalid glob %q: %w", p, err)
		}
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	s.name = name
	s.jobID = jobID
	s.sourceID = sourceID
	s.verify = verify
	s.concurrency = concurrency
	s.cfg = cfg
	return nil
}

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	img, digest, ref, err := s.loadImage(ctx)
	if err != nil {
		return fmt.Errorf("docker-image: load image %q: %w", s.cfg.Image, err)
	}

	// Emit the image config blob (ENV, labels, cmd, entrypoint).
	if err := s.emitConfig(ctx, img, ref, digest, ch); err != nil {
		return err
	}

	// Emit text files from each layer.
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("docker-image: get layers: %w", err)
	}
	for _, layer := range layers {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.emitLayer(ctx, layer, ref, digest, ch); err != nil {
			return err
		}
	}
	return nil
}

// loadImage fetches the image from registry or daemon and returns the v1.Image,
// its manifest digest string, and a canonical reference string.
func (s *Source) loadImage(ctx context.Context) (v1.Image, string, string, error) {
	ref := s.cfg.Image

	if s.cfg.FromDaemon {
		r, err := name.ParseReference(ref)
		if err != nil {
			return nil, "", "", fmt.Errorf("parse image ref: %w", err)
		}
		img, err := daemon.Image(r, daemon.WithContext(ctx))
		if err != nil {
			return nil, "", "", fmt.Errorf("load from daemon: %w", err)
		}
		digest, err := digestString(img)
		if err != nil {
			return nil, "", "", err
		}
		return img, digest, r.String(), nil
	}

	opts := s.craneOptions(ctx)
	img, err := crane.Pull(ref, opts...)
	if err != nil {
		return nil, "", "", fmt.Errorf("pull from registry: %w", err)
	}
	// Resolve the canonical reference with digest.
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, "", "", fmt.Errorf("parse image ref: %w", err)
	}
	digest, err := digestString(img)
	if err != nil {
		return nil, "", "", err
	}
	return img, digest, r.String(), nil
}

func (s *Source) craneOptions(ctx context.Context) []crane.Option {
	opts := []crane.Option{crane.WithContext(ctx)}
	if s.cfg.Platform != "" {
		p, err := parsePlatform(s.cfg.Platform)
		if err == nil {
			opts = append(opts, crane.WithPlatform(p))
		}
	}
	if s.cfg.Username != "" || s.cfg.Password != "" {
		opts = append(opts, crane.WithAuth(&authn.Basic{
			Username: s.cfg.Username,
			Password: s.cfg.Password,
		}))
	}
	return opts
}

// emitConfig extracts ENV, labels, Cmd, Entrypoint from the image config and
// emits them as a single KEY=VALUE text chunk so detectors can match secrets
// baked into the image environment.
func (s *Source) emitConfig(ctx context.Context, img v1.Image, ref, digest string, ch chan<- *sources.Chunk) error {
	cf, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("docker-image: read config: %w", err)
	}

	var lines []string
	lines = append(lines, cf.Config.Env...)
	for k, v := range cf.Config.Labels {
		lines = append(lines, k+"="+v)
	}
	if len(cf.Config.Cmd) > 0 {
		lines = append(lines, "CMD="+strings.Join(cf.Config.Cmd, " "))
	}
	if len(cf.Config.Entrypoint) > 0 {
		lines = append(lines, "ENTRYPOINT="+strings.Join(cf.Config.Entrypoint, " "))
	}
	if len(lines) == 0 {
		return nil
	}
	data := []byte(strings.Join(lines, "\n"))
	return sendChunk(ctx, ch, &sources.Chunk{
		SourceID:   s.sourceID,
		SourceType: sources.SourceDockerImage,
		SourceName: s.name,
		Data:       data,
		SourceMetadata: sources.Metadata{
			DockerImage: &sources.DockerImageMeta{
				Image:  ref,
				Digest: digest,
				Layer:  "config",
				File:   "",
			},
		},
	})
}

// emitLayer streams files from one OCI layer (a compressed tar) and emits
// text files as individual chunks.
func (s *Source) emitLayer(ctx context.Context, layer v1.Layer, ref, imageDigest string, ch chan<- *sources.Chunk) error {
	layerDigest, err := layer.DiffID()
	if err != nil {
		return fmt.Errorf("docker-image: layer diffid: %w", err)
	}
	layerDigestStr := layerDigest.String()

	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("docker-image: open layer %s: %w", layerDigestStr, err)
	}
	defer rc.Close()

	tr := tar.NewReader(io.LimitReader(rc, s.cfg.MaxLayerSize))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Corrupt entry — skip the rest of this layer.
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size == 0 || hdr.Size > s.cfg.MaxLayerSize {
			continue
		}
		if !s.pathAllowed(hdr.Name) {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(tr, s.cfg.MaxLayerSize))
		if err != nil {
			continue
		}
		if isBinary(data) {
			continue
		}

		chunk := &sources.Chunk{
			SourceID:   s.sourceID,
			SourceType: sources.SourceDockerImage,
			SourceName: s.name,
			Data:       data,
			SourceMetadata: sources.Metadata{
				DockerImage: &sources.DockerImageMeta{
					Image:  ref,
					Digest: imageDigest,
					Layer:  layerDigestStr,
					File:   hdr.Name,
				},
			},
		}
		if err := sendChunk(ctx, ch, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (s *Source) pathAllowed(p string) bool {
	base := filepath.Base(p)
	for _, pat := range s.cfg.Exclude {
		if matchGlob(pat, p) || matchGlob(pat, base) {
			return false
		}
	}
	if len(s.cfg.Include) == 0 {
		return true
	}
	for _, pat := range s.cfg.Include {
		if matchGlob(pat, p) || matchGlob(pat, base) {
			return true
		}
	}
	return false
}

func matchGlob(pattern, name string) bool {
	ok, _ := filepath.Match(pattern, name)
	return ok
}

func isBinary(b []byte) bool {
	n := len(b)
	if n > binarySniffLen {
		n = binarySniffLen
	}
	return bytes.IndexByte(b[:n], 0x00) >= 0
}

func sendChunk(ctx context.Context, ch chan<- *sources.Chunk, chunk *sources.Chunk) error {
	select {
	case ch <- chunk:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func digestString(img v1.Image) (string, error) {
	h, err := img.Digest()
	if err != nil {
		return "", fmt.Errorf("docker-image: compute digest: %w", err)
	}
	return h.String(), nil
}

func parsePlatform(s string) (*v1.Platform, error) {
	parts := strings.SplitN(s, "/", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid platform %q (want OS/arch)", s)
	}
	p := &v1.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	return p, nil
}

var _ sources.Source = (*Source)(nil)
