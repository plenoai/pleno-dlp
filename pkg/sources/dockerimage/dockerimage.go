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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"

	"github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/engine"
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

type Source struct {
	name        string
	jobID       int64
	sourceID    int64
	verify      bool
	concurrency int
	cfg         Config

	hasPreviousState bool
	previousState    *incrementalState
	nextState        *incrementalState
}

// incrementalState records which layer diffIDs a previous scan already
// covered. Layers are content-addressed and immutable, so membership alone
// (no size/mtime comparison) is a sufficient and exact skip condition.
type incrementalState struct {
	Version int             `json:"version"`
	Layers  map[string]bool `json:"layers,omitempty"`
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
	return s.chunksFromImage(ctx, img, ref, digest, ch)
}

// chunksFromImage runs the scan against an already-resolved v1.Image, so
// tests can exercise it against a synthetic image without a registry/daemon.
func (s *Source) chunksFromImage(ctx context.Context, img v1.Image, ref, digest string, ch chan<- *sources.Chunk) error {
	if err := s.emitConfig(ctx, img, ref, digest, ch); err != nil {
		return err
	}

	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("docker-image: get layers: %w", err)
	}
	s.nextState = &incrementalState{Version: 1, Layers: map[string]bool{}}
	var coverage []engine.ScanFailure
	for _, layer := range layers {
		if err := ctx.Err(); err != nil {
			return err
		}
		diffID, err := layer.DiffID()
		if err != nil {
			return fmt.Errorf("docker-image: layer diffid: %w", err)
		}
		layerDigestStr := diffID.String()
		if s.layerScanned(layerDigestStr) {
			s.nextState.Layers[layerDigestStr] = true
			continue
		}
		gap, err := s.emitLayer(ctx, layer, layerDigestStr, ref, digest, ch)
		if err != nil {
			return err
		}
		if gap != nil {
			// A layer read only partially stays out of the incremental
			// state so the next run rescans it (#975).
			coverage = append(coverage, engine.ScanFailure{
				Kind:   engine.FailureSource,
				Source: ref + "@" + layerDigestStr,
				Err:    gap,
			})
			continue
		}
		s.nextState.Layers[layerDigestStr] = true
	}
	if len(coverage) > 0 {
		return &engine.DegradedError{
			Total:    len(coverage),
			Counts:   map[engine.FailureKind]int{engine.FailureSource: len(coverage)},
			Failures: coverage,
		}
	}
	return nil
}

func (s *Source) layerScanned(diffID string) bool {
	return s.hasPreviousState && s.previousState != nil && s.previousState.Layers[diffID]
}

func (s *Source) SetIncrementalState(previous json.RawMessage) error {
	s.hasPreviousState = false
	s.previousState = nil
	s.nextState = nil
	if len(previous) == 0 || string(previous) == "null" {
		return nil
	}
	var state incrementalState
	if err := json.Unmarshal(previous, &state); err != nil {
		return err
	}
	if state.Layers == nil {
		state.Layers = map[string]bool{}
	}
	s.hasPreviousState = true
	s.previousState = &state
	return nil
}

func (s *Source) IncrementalState() json.RawMessage {
	if s.nextState == nil {
		return nil
	}
	data, err := json.Marshal(s.nextState)
	if err != nil {
		return nil
	}
	return data
}

// ResourceFingerprint hashes the source config plus the image's config
// digest and per-layer diffIDs, so an unchanged image (by content, not just
// by tag) short-circuits the scan.
func (s *Source) ResourceFingerprint(ctx context.Context) (string, error) {
	img, digest, ref, err := s.loadImage(ctx)
	if err != nil {
		return "", fmt.Errorf("docker-image: load image for fingerprint: %w", err)
	}
	return s.fingerprintFromImage(img, ref, digest)
}

// fingerprintFromImage computes the fingerprint from an already-resolved
// v1.Image, so tests can exercise it against a synthetic image.
func (s *Source) fingerprintFromImage(img v1.Image, ref, digest string) (string, error) {
	cfgHash, err := img.ConfigName()
	if err != nil {
		return "", fmt.Errorf("docker-image: config digest: %w", err)
	}
	layers, err := img.Layers()
	if err != nil {
		return "", fmt.Errorf("docker-image: layers for fingerprint: %w", err)
	}

	h := sha256.New()
	writeHash(h, "docker-image-v1")
	writeHash(h, ref)
	writeHash(h, s.cfg.Platform)
	writeHash(h, strconv.FormatInt(s.cfg.MaxLayerSize, 10))
	writeHash(h, strings.Join(s.cfg.Include, ","))
	writeHash(h, strings.Join(s.cfg.Exclude, ","))
	writeHash(h, digest)
	writeHash(h, cfgHash.String())
	for _, layer := range layers {
		diffID, err := layer.DiffID()
		if err != nil {
			return "", fmt.Errorf("docker-image: layer diffid for fingerprint: %w", err)
		}
		writeHash(h, diffID.String())
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeHash(h hash.Hash, s string) {
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{0})
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

// rawRemainderFile names the chunk that carries the unparsed bytes of a
// corrupt or truncated layer tar.
const rawRemainderFile = "(corrupt layer remainder)"

// maxRawCapture bounds how many already-consumed bytes (padding, skipped
// entry bodies, the failing header) are retained for the raw fallback.
const maxRawCapture = 1 << 20

// boundedCapture records at most limit bytes written since the last reset.
type boundedCapture struct {
	buf   []byte
	limit int
}

func (b *boundedCapture) Write(p []byte) (int, error) {
	if room := b.limit - len(b.buf); room > 0 {
		b.buf = append(b.buf, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (b *boundedCapture) reset() { b.buf = b.buf[:0] }

// emitLayer streams files from one OCI layer (a compressed tar) and emits
// text files as individual chunks. A corrupt or truncated tar does not stop
// silently: the unparsed remainder is emitted as one raw chunk (consistent
// with the #970 archive fallback) and returned as gap so the caller records
// a coverage failure and keeps the layer out of the incremental state
// (#975). err is reserved for fatal errors (cancellation).
func (s *Source) emitLayer(ctx context.Context, layer v1.Layer, layerDigestStr, ref, imageDigest string, ch chan<- *sources.Chunk) (gap error, err error) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("docker-image: open layer %s: %w", layerDigestStr, err), nil
	}
	defer rc.Close()

	newChunk := func(file string, data []byte) *sources.Chunk {
		return &sources.Chunk{
			SourceID:   s.sourceID,
			SourceType: sources.SourceDockerImage,
			SourceName: s.name,
			Data:       data,
			SourceMetadata: sources.Metadata{
				DockerImage: &sources.DockerImageMeta{
					Image:  ref,
					Digest: imageDigest,
					Layer:  layerDigestStr,
					File:   file,
				},
			},
		}
	}

	limited := io.LimitReader(rc, s.cfg.MaxLayerSize)
	capture := &boundedCapture{limit: maxRawCapture}
	tr := tar.NewReader(io.TeeReader(limited, capture))
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		capture.reset()
		hdr, nerr := tr.Next()
		if errors.Is(nerr, io.EOF) {
			return nil, nil
		}
		if nerr != nil {
			rest, rerr := io.ReadAll(io.LimitReader(limited, s.cfg.MaxLayerSize))
			raw := append(append([]byte{}, capture.buf...), rest...)
			if len(raw) > 0 {
				if err := sendChunk(ctx, ch, newChunk(rawRemainderFile, raw)); err != nil {
					return nil, err
				}
			}
			gap := fmt.Errorf("docker-image: layer %s: corrupt-archive: %w", layerDigestStr, nerr)
			if rerr != nil {
				gap = fmt.Errorf("%w (remainder read: %v)", gap, rerr)
			}
			return gap, nil
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

		data, rerr := io.ReadAll(io.LimitReader(tr, s.cfg.MaxLayerSize))
		if rerr != nil {
			// Truncated entry body: scan what was read, then report the gap.
			if len(data) > 0 {
				if err := sendChunk(ctx, ch, newChunk(hdr.Name, data)); err != nil {
					return nil, err
				}
			}
			return fmt.Errorf("docker-image: layer %s: corrupt-entry %s: %w", layerDigestStr, hdr.Name, rerr), nil
		}
		// Archives (and orphan split volumes) are binary but must reach the
		// engine, which expands them or reports the gap and scans the raw
		// bytes (#970).
		if isBinary(data) && !archive.LooksLikeArchive(data) && !archive.OrphanVolumeName(filepath.Base(hdr.Name)) {
			continue
		}
		if err := sendChunk(ctx, ch, newChunk(hdr.Name, data)); err != nil {
			return nil, err
		}
	}
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
var _ sources.ResourceFingerprinter = (*Source)(nil)
var _ sources.IncrementalStateSource = (*Source)(nil)
