// Package gcs lists objects in a GCS bucket and emits one chunk per
// text object. Authentication uses Application Default Credentials
// (GOOGLE_APPLICATION_CREDENTIALS, gcloud auth, Workload Identity) —
// no pleno-dlp-specific auth.
package gcs

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
	"strconv"
	"strings"

	"cloud.google.com/go/storage"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	defaultMaxObjectSize int64 = 10 * 1024 * 1024 // 10 MiB
	binarySniffLen             = 512
)

func init() {
	sources.Register(sources.SourceGCS, func() sources.Source { return &Source{} })
}

// Config is the JSON configuration for the GCS source. ServiceAccountJSON
// is optional — when empty the SDK resolves credentials via ADC.
type Config struct {
	Bucket             string   `json:"bucket"`
	Prefix             string   `json:"prefix,omitempty"`
	ServiceAccountJSON string   `json:"service_account_json,omitempty"`
	MaxSizeBytes       int64    `json:"max_size_bytes,omitempty"`
	Include            []string `json:"include,omitempty"`
	Exclude            []string `json:"exclude,omitempty"`
}

type Source struct {
	name        string
	jobID       int64
	sourceID    int64
	verify      bool
	concurrency int

	bucket             string
	prefix             string
	maxSizeBytes       int64
	include            []string
	exclude            []string
	serviceAccountJSON string

	hasPreviousState bool
	previousState    *incrementalState
	nextState        *incrementalState
}

type incrementalState struct {
	Version int                               `json:"version"`
	Objects map[string]objectIncrementalState `json:"objects"`
}

type objectIncrementalState struct {
	Generation int64  `json:"generation,omitempty"`
	ETag       string `json:"etag,omitempty"`
	Size       int64  `json:"size,omitempty"`
	Updated    string `json:"updated,omitempty"`
}

func (s *Source) Type() sources.SourceType { return sources.SourceGCS }

func (s *Source) Init(_ context.Context, name string, jobID, sourceID int64, verify bool, cfgJSON []byte, concurrency int) error {
	var cfg Config
	if len(cfgJSON) > 0 {
		if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
			return fmt.Errorf("gcs: invalid config json: %w", err)
		}
	}
	if cfg.Bucket == "" {
		return errors.New("gcs: config.bucket must be set")
	}
	if cfg.MaxSizeBytes <= 0 {
		cfg.MaxSizeBytes = defaultMaxObjectSize
	}
	for _, p := range append(append([]string{}, cfg.Include...), cfg.Exclude...) {
		if _, err := filepath.Match(p, ""); err != nil {
			return fmt.Errorf("gcs: invalid glob %q: %w", p, err)
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
	s.bucket = cfg.Bucket
	s.prefix = cfg.Prefix
	s.maxSizeBytes = cfg.MaxSizeBytes
	s.include = cfg.Include
	s.exclude = cfg.Exclude
	s.serviceAccountJSON = cfg.ServiceAccountJSON
	return nil
}

func (s *Source) newClient(ctx context.Context) (*storage.Client, error) {
	if s.serviceAccountJSON != "" {
		creds, err := google.CredentialsFromJSON(ctx, []byte(s.serviceAccountJSON), storage.ScopeReadOnly)
		if err != nil {
			return nil, fmt.Errorf("gcs: parse service account JSON: %w", err)
		}
		return storage.NewClient(ctx, option.WithCredentials(creds))
	}
	return storage.NewClient(ctx)
}

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	client, err := s.newClient(ctx)
	if err != nil {
		return fmt.Errorf("gcs: create client: %w", err)
	}
	defer client.Close()

	s.nextState = &incrementalState{Version: 1, Objects: map[string]objectIncrementalState{}}
	bkt := client.Bucket(s.bucket)

	query := &storage.Query{}
	if s.prefix != "" {
		query.Prefix = s.prefix
	}

	it := bkt.Objects(ctx, query)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return fmt.Errorf("gcs: list objects: %w", err)
		}
		if strings.HasSuffix(attrs.Name, "/") {
			continue
		}
		if attrs.Size > s.maxSizeBytes {
			continue
		}
		if !s.keyAllowed(attrs.Name) {
			continue
		}
		objState := stateForAttrs(attrs)
		s.nextState.Objects[attrs.Name] = objState
		if s.objectUnchanged(attrs.Name, objState) {
			continue
		}
		if err := s.emitObject(ctx, bkt, attrs.Name, attrs.Generation, ch); err != nil {
			return err
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

func (s *Source) objectUnchanged(name string, current objectIncrementalState) bool {
	if !s.hasPreviousState || s.previousState == nil {
		return false
	}
	prev, ok := s.previousState.Objects[name]
	return ok && prev == current
}

// ResourceFingerprint hashes bucket + prefix + object listing (name + generation).
func (s *Source) ResourceFingerprint(ctx context.Context) (string, error) {
	client, err := s.newClient(ctx)
	if err != nil {
		return "", fmt.Errorf("gcs: create client for fingerprint: %w", err)
	}
	defer client.Close()

	bkt := client.Bucket(s.bucket)
	query := &storage.Query{}
	if s.prefix != "" {
		query.Prefix = s.prefix
	}

	h := sha256.New()
	writeHash(h, "gcs-v1")
	writeHash(h, s.bucket)
	writeHash(h, s.prefix)

	type entry struct {
		name       string
		generation int64
	}
	var entries []entry

	it := bkt.Objects(ctx, query)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("gcs: list objects for fingerprint: %w", err)
		}
		if strings.HasSuffix(attrs.Name, "/") {
			continue
		}
		if attrs.Size > s.maxSizeBytes {
			continue
		}
		if !s.keyAllowed(attrs.Name) {
			continue
		}
		entries = append(entries, entry{name: attrs.Name, generation: attrs.Generation})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	for _, e := range entries {
		writeHash(h, e.name)
		writeHash(h, strconv.FormatInt(e.generation, 10))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (s *Source) emitObject(ctx context.Context, bkt *storage.BucketHandle, name string, generation int64, ch chan<- *sources.Chunk) error {
	obj := bkt.Object(name).Generation(generation)
	r, err := obj.NewReader(ctx)
	if err != nil {
		// Per-object errors are skipped, not fatal.
		return nil
	}
	defer r.Close()

	data, err := io.ReadAll(io.LimitReader(r, s.maxSizeBytes))
	if err != nil {
		return nil
	}
	if isBinary(data) {
		return nil
	}

	chunk := &sources.Chunk{
		SourceID:   s.sourceID,
		SourceType: sources.SourceGCS,
		SourceName: s.name,
		Data:       data,
		SourceMetadata: sources.Metadata{
			GCS: &sources.GCSMeta{
				Bucket:     s.bucket,
				Object:     name,
				Generation: generation,
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

func stateForAttrs(attrs *storage.ObjectAttrs) objectIncrementalState {
	return objectIncrementalState{
		Generation: attrs.Generation,
		ETag:       attrs.Etag,
		Size:       attrs.Size,
		Updated:    attrs.Updated.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	}
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
