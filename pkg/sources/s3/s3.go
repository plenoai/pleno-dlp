// Package s3 lists objects in an S3 bucket and emits one chunk per
// text object. Authentication uses the default AWS credential chain
// (env vars, IAM role, ~/.aws/config) — no pleno-dlp-specific auth.
package s3

import (
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
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	defaultMaxObjectSize int64 = 10 * 1024 * 1024 // 10 MiB
	binarySniffLen             = 512
)

func init() {
	sources.Register(sources.SourceS3, func() sources.Source { return &Source{} })
}

// Config is the JSON configuration for the S3 source. Region and
// endpoint are optional — when empty the SDK resolves them from the
// default credential chain. Endpoint is useful for S3-compatible
// stores (MinIO, localstack).
type Config struct {
	Bucket       string   `json:"bucket"`
	Prefix       string   `json:"prefix,omitempty"`
	Region       string   `json:"region,omitempty"`
	Endpoint     string   `json:"endpoint,omitempty"`
	MaxSizeBytes int64    `json:"max_size_bytes,omitempty"`
	Include      []string `json:"include,omitempty"`
	Exclude      []string `json:"exclude,omitempty"`
}

type Source struct {
	name        string
	jobID       int64
	sourceID    int64
	verify      bool
	concurrency int

	bucket       string
	prefix       string
	maxSizeBytes int64
	include      []string
	exclude      []string
	awsCfg       aws.Config

	hasPreviousState bool
	previousState    *incrementalState
	nextState        *incrementalState
}

type incrementalState struct {
	Version int                               `json:"version"`
	Objects map[string]objectIncrementalState `json:"objects"`
}

type objectIncrementalState struct {
	ETag         string `json:"etag,omitempty"`
	Size         int64  `json:"size,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
}

func (s *Source) Type() sources.SourceType { return sources.SourceS3 }

func (s *Source) Init(ctx context.Context, name string, jobID, sourceID int64, verify bool, cfgJSON []byte, concurrency int) error {
	var cfg Config
	if len(cfgJSON) > 0 {
		if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
			return fmt.Errorf("s3: invalid config json: %w", err)
		}
	}
	if cfg.Bucket == "" {
		return errors.New("s3: config.bucket must be set")
	}
	if cfg.MaxSizeBytes <= 0 {
		cfg.MaxSizeBytes = defaultMaxObjectSize
	}
	for _, p := range append(append([]string{}, cfg.Include...), cfg.Exclude...) {
		if _, err := filepath.Match(p, ""); err != nil {
			return fmt.Errorf("s3: invalid glob %q: %w", p, err)
		}
	}

	var opts []func(*config.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, config.WithRegion(cfg.Region))
	}
	awsCfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("s3: load aws config: %w", err)
	}

	if concurrency <= 0 {
		concurrency = 1
	}
	s.name = name
	s.jobID = jobID
	s.sourceID = sourceID
	s.verify = verify
	s.concurrency = concurrency
	s.bucket = cfg.Bucket
	s.prefix = cfg.Prefix
	s.maxSizeBytes = cfg.MaxSizeBytes
	s.include = cfg.Include
	s.exclude = cfg.Exclude
	s.awsCfg = awsCfg

	if cfg.Endpoint != "" {
		s.awsCfg.BaseEndpoint = aws.String(cfg.Endpoint)
	}
	return nil
}

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	client := s3.NewFromConfig(s.awsCfg)
	s.nextState = &incrementalState{Version: 1, Objects: map[string]objectIncrementalState{}}

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
	}
	if s.prefix != "" {
		input.Prefix = aws.String(s.prefix)
	}

	paginator := s3.NewListObjectsV2Paginator(client, input)
	for paginator.HasMorePages() {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("s3: list objects: %w", err)
		}
		for _, obj := range page.Contents {
			if err := ctx.Err(); err != nil {
				return err
			}
			key := aws.ToString(obj.Key)
			if strings.HasSuffix(key, "/") {
				continue
			}
			if obj.Size != nil && *obj.Size > s.maxSizeBytes {
				continue
			}
			if !s.keyAllowed(key) {
				continue
			}
			objState := stateForObject(obj)
			s.nextState.Objects[key] = objState
			if s.objectUnchanged(key, objState) {
				continue
			}
			if err := s.emitObject(ctx, client, key, ch); err != nil {
				return err
			}
		}
	}
	return nil
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
	if state.Objects == nil {
		state.Objects = map[string]objectIncrementalState{}
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

func (s *Source) objectUnchanged(key string, current objectIncrementalState) bool {
	if !s.hasPreviousState || s.previousState == nil {
		return false
	}
	prev, ok := s.previousState.Objects[key]
	return ok && prev == current
}

// ResourceFingerprint hashes bucket + prefix + object listing (key + ETag).
func (s *Source) ResourceFingerprint(ctx context.Context) (string, error) {
	client := s3.NewFromConfig(s.awsCfg)
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
	}
	if s.prefix != "" {
		input.Prefix = aws.String(s.prefix)
	}

	h := sha256.New()
	writeHash(h, "s3-v1")
	writeHash(h, s.bucket)
	writeHash(h, s.prefix)

	type entry struct {
		key  string
		etag string
	}
	var entries []entry

	paginator := s3.NewListObjectsV2Paginator(client, input)
	for paginator.HasMorePages() {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("s3: list objects for fingerprint: %w", err)
		}
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			if strings.HasSuffix(key, "/") {
				continue
			}
			if obj.Size != nil && *obj.Size > s.maxSizeBytes {
				continue
			}
			if !s.keyAllowed(key) {
				continue
			}
			entries = append(entries, entry{
				key:  key,
				etag: aws.ToString(obj.ETag),
			})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })
	for _, e := range entries {
		writeHash(h, e.key)
		writeHash(h, e.etag)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Source) emitObject(ctx context.Context, client *s3.Client, key string, ch chan<- *sources.Chunk) error {
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		// Per-object errors are skipped, not fatal.
		return nil
	}
	defer out.Body.Close()

	data, err := io.ReadAll(io.LimitReader(out.Body, s.maxSizeBytes))
	if err != nil {
		return nil
	}
	if isBinary(data) {
		return nil
	}

	chunk := &sources.Chunk{
		SourceID:   s.sourceID,
		SourceType: sources.SourceS3,
		SourceName: s.name,
		Data:       data,
		SourceMetadata: sources.Metadata{
			S3: &sources.S3Meta{
				Bucket:    s.bucket,
				Key:       key,
				VersionID: aws.ToString(out.VersionId),
				ETag:      aws.ToString(out.ETag),
			},
		},
	}
	select {
	case ch <- chunk:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func stateForObject(obj types.Object) objectIncrementalState {
	state := objectIncrementalState{
		ETag: aws.ToString(obj.ETag),
	}
	if obj.Size != nil {
		state.Size = *obj.Size
	}
	if obj.LastModified != nil {
		state.LastModified = obj.LastModified.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	}
	return state
}

func (s *Source) keyAllowed(key string) bool {
	base := filepath.Base(key)
	for _, pat := range s.exclude {
		if matchGlob(pat, key) || matchGlob(pat, base) {
			return false
		}
	}
	if len(s.include) == 0 {
		return true
	}
	for _, pat := range s.include {
		if matchGlob(pat, key) || matchGlob(pat, base) {
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

func writeHash(h hash.Hash, s string) {
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{0})
}

var _ sources.Source = (*Source)(nil)
var _ sources.ResourceFingerprinter = (*Source)(nil)
var _ sources.IncrementalStateSource = (*Source)(nil)
