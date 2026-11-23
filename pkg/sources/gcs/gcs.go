// Package gcs lists objects in a GCS bucket and emits one chunk per text
// object and one chunk per archive object, which the engine expands under
// its archive budgets. Multi-volume archives ("<name>.vol1.egg",
// "<name>.zip.001", ...) are joined across objects with archive.JoinVolumes
// before expansion. Authentication uses Application Default Credentials
// (GOOGLE_APPLICATION_CREDENTIALS, gcloud auth, Workload Identity) — no
// pleno-dlp-specific auth.
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
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"cloud.google.com/go/storage"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	"github.com/plenoai/pleno-dlp/pkg/sources/volumeset"
)

const (
	defaultMaxObjectSize int64 = 10 * 1024 * 1024 // 10 MiB
	maxArchiveObjectSize int64 = 50 * 1024 * 1024 // 50 MiB compressed, shared with S3
	binarySniffLen             = 512
	maxCoverageExamples        = 32
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

	// openBucket is replaced in tests with a fake; nil uses the GCS client.
	openBucket func(ctx context.Context) (bucketAPI, func(), error)

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
		creds, err := google.CredentialsFromJSONWithType(ctx, []byte(s.serviceAccountJSON), google.ServiceAccount, storage.ScopeReadOnly)
		if err != nil {
			return nil, fmt.Errorf("gcs: parse service account JSON: %w", err)
		}
		return storage.NewClient(ctx, option.WithCredentials(creds))
	}
	return storage.NewClient(ctx)
}

func (s *Source) connect(ctx context.Context) (bucketAPI, func(), error) {
	if s.openBucket != nil {
		return s.openBucket(ctx)
	}
	client, err := s.newClient(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("gcs: create client: %w", err)
	}
	return storageBucket{bkt: client.Bucket(s.bucket)}, func() { _ = client.Close() }, nil
}

// eligible applies the listing filters shared by Chunks and the fingerprint.
func (s *Source) eligible(o objectInfo) bool {
	return !strings.HasSuffix(o.Name, "/") && o.State.Size <= s.maxSizeBytes && s.keyAllowed(o.Name)
}

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	bkt, closeFn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer closeFn()

	s.nextState = &incrementalState{Version: 1, Objects: map[string]objectIncrementalState{}}
	var coverage []engine.ScanFailure
	coverageTotal := 0
	recordFailure := func(name string, err error) {
		coverageTotal++
		if len(coverage) < maxCoverageExamples {
			source := "gcs-listing"
			if name != "" {
				source = safeObjectLocator(name)
			}
			coverage = append(coverage, engine.ScanFailure{Kind: engine.FailureSource, Source: source, Err: err})
		}
	}
	complete := func(o objectInfo) { s.nextState.Objects[o.Name] = o.State }

	// Volume objects are held back until listing ends so siblings that
	// span pages are grouped before dispatch.
	volumes := volumeset.New[objectInfo]()
	listErr := bkt.List(ctx, s.prefix, func(o objectInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !s.eligible(o) {
			return nil
		}
		if s.objectUnchanged(o.Name, o.State) || o.State.Size == 0 {
			complete(o)
			return nil
		}
		if volumes.Add(o.Name, o.State.Size, o) {
			return nil
		}
		if err := s.emitObject(ctx, bkt, o, ch); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			recordFailure(o.Name, err)
			return nil
		}
		complete(o)
		return nil
	})
	if err := ctx.Err(); err != nil {
		return err
	}
	if listErr != nil {
		recordFailure("", redactCoverageError("list objects", listErr))
	}
	for _, job := range volumes.Jobs(s.archiveLimit()) {
		all := job.All()
		if len(job.Volumes) > 0 && s.allUnchanged(all) {
			for _, m := range all {
				complete(m.Item)
			}
			continue
		}
		var err error
		if len(job.Volumes) == 0 {
			err = s.emitObject(ctx, bkt, job.Head.Item, ch)
		} else {
			err = s.emitVolumes(ctx, bkt, job, ch)
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			recordFailure(job.Head.Key, err)
			continue
		}
		// A set is checkpointed only as a whole: a failure in any volume
		// leaves every volume eligible for the next run.
		for _, m := range all {
			complete(m.Item)
		}
	}
	if coverageTotal > 0 {
		s.nextState = &incrementalState{Version: 1, Objects: map[string]objectIncrementalState{}}
		return &engine.DegradedError{
			Total:    coverageTotal,
			Counts:   map[engine.FailureKind]int{engine.FailureSource: coverageTotal},
			Failures: coverage,
		}
	}
	return nil
}

func (s *Source) archiveLimit() int64 { return min(s.maxSizeBytes, maxArchiveObjectSize) }

func (s *Source) allUnchanged(ms []volumeset.Member[objectInfo]) bool {
	for _, m := range ms {
		if !s.objectUnchanged(m.Key, m.Item.State) {
			return false
		}
	}
	return true
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
	bkt, closeFn, err := s.connect(ctx)
	if err != nil {
		return "", err
	}
	defer closeFn()

	h := sha256.New()
	writeHash(h, "gcs-v1")
	writeHash(h, s.bucket)
	writeHash(h, s.prefix)

	type entry struct {
		name       string
		generation int64
	}
	var entries []entry
	err = bkt.List(ctx, s.prefix, func(o objectInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.eligible(o) {
			entries = append(entries, entry{name: o.Name, generation: o.Generation})
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("gcs: list objects for fingerprint: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })
	for _, e := range entries {
		writeHash(h, e.name)
		writeHash(h, strconv.FormatInt(e.generation, 10))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
