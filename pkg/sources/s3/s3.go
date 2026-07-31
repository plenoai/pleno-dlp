// Package s3 lists objects in an S3 bucket and emits bounded text chunks or
// intact, size-limited archives. Authentication uses the default AWS
// credential chain, optionally followed by one or two assumed roles.
package s3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	defaultMaxObjectSize int64 = 250 * 1024 * 1024 // 250 MiB
	maxObjectSizeLimit         = defaultMaxObjectSize
	maxArchiveObjectSize int64 = 50 * 1024 * 1024 // 50 MiB compressed
	binarySniffLen             = 512
	// Source-level chunks keep large text objects out of memory while the
	// overlap preserves detector inputs up to 64 KiB across boundaries.
	objectChunkSize        = 1 * 1024 * 1024
	objectChunkOverlap     = 64 * 1024
	defaultRoleSessionName = "pleno-dlp"
	maxCoverageExamples    = 32
)

var errArchiveObjectTooLarge = errors.New("archive object exceeds compressed size limit")

func init() {
	sources.Register(sources.SourceS3, func() sources.Source { return &Source{} })
}

// Config is the JSON configuration for the S3 source. Region and
// endpoint are optional — when empty the SDK resolves them from the
// default credential chain. Endpoint is useful for S3-compatible
// stores (MinIO, localstack).
type Config struct {
	Bucket          string   `json:"bucket"`
	Prefix          string   `json:"prefix,omitempty"`
	Region          string   `json:"region,omitempty"`
	Endpoint        string   `json:"endpoint,omitempty"`
	RoleARNs        []string `json:"role_arns,omitempty"`
	RoleSessionName string   `json:"role_session_name,omitempty"`
	MaxSizeBytes    int64    `json:"max_size_bytes,omitempty"`
	Include         []string `json:"include,omitempty"`
	Exclude         []string `json:"exclude,omitempty"`
}

type s3API interface {
	s3.ListObjectsV2APIClient
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
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

	// client and progress are narrow test seams. Production uses the SDK
	// client and stderr.
	client   s3API
	progress io.Writer

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

type assumeRoleProviderFactory func(aws.Config, string, string) aws.CredentialsProvider

type objectJob struct {
	key   string
	state objectIncrementalState
}

type objectOutcome struct {
	bytes      int64
	binary     bool
	empty      bool
	checkpoint bool
}

type scanSummary struct {
	listed          atomic.Int64
	scanned         atomic.Int64
	bytes           atomic.Int64
	unchanged       atomic.Int64
	empty           atomic.Int64
	oversize        atomic.Int64
	archiveOversize atomic.Int64
	binary          atomic.Int64
	filtered        atomic.Int64
	directory       atomic.Int64
	failed          atomic.Int64
}

func (s *scanSummary) String() string {
	return fmt.Sprintf(
		"s3: scan complete: listed=%d scanned=%d bytes=%d unchanged=%d empty=%d oversize=%d archive_oversize=%d binary=%d filtered=%d directory=%d failed=%d",
		s.listed.Load(), s.scanned.Load(), s.bytes.Load(), s.unchanged.Load(),
		s.empty.Load(), s.oversize.Load(), s.archiveOversize.Load(), s.binary.Load(), s.filtered.Load(),
		s.directory.Load(), s.failed.Load(),
	)
}

type redactedCoverageError struct {
	operation string
	cause     error
}

func (e *redactedCoverageError) Error() string { return e.operation + " failed" }
func (e *redactedCoverageError) Unwrap() error { return e.cause }

func redactCoverageError(operation string, cause error) error {
	return &redactedCoverageError{operation: operation, cause: cause}
}

func safeObjectLocator(key string) string {
	sum := sha256.Sum256([]byte(key))
	return fmt.Sprintf("s3-object-sha256:%x", sum)
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
	if cfg.MaxSizeBytes > maxObjectSizeLimit {
		return fmt.Errorf("s3: config.max_size_bytes must be at most %d bytes (250 MiB)", maxObjectSizeLimit)
	}
	if len(cfg.RoleARNs) > 2 {
		return errors.New("s3: config.role_arns supports at most two sequential roles")
	}
	for _, roleARN := range cfg.RoleARNs {
		if strings.TrimSpace(roleARN) == "" || roleARN != strings.TrimSpace(roleARN) {
			return errors.New("s3: config.role_arns entries must be non-empty and contain no surrounding whitespace")
		}
	}
	if cfg.RoleSessionName == "" {
		cfg.RoleSessionName = defaultRoleSessionName
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
	awsCfg = applyAssumeRoleChain(awsCfg, cfg.RoleARNs, cfg.RoleSessionName, newAssumeRoleProvider)

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

func applyAssumeRoleChain(cfg aws.Config, roleARNs []string, sessionName string, factory assumeRoleProviderFactory) aws.Config {
	for _, roleARN := range roleARNs {
		cfg.Credentials = aws.NewCredentialsCache(factory(cfg, roleARN, sessionName))
	}
	return cfg
}

func newAssumeRoleProvider(cfg aws.Config, roleARN, sessionName string) aws.CredentialsProvider {
	return stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), roleARN, func(opts *stscreds.AssumeRoleOptions) {
		opts.RoleSessionName = sessionName
	})
}

func (s *Source) s3Client() s3API {
	if s.client != nil {
		return s.client
	}
	return s3.NewFromConfig(s.awsCfg, func(opts *s3.Options) {
		opts.DisableLogOutputChecksumValidationSkipped = true
	})
}

func (s *Source) progressWriter() io.Writer {
	if s.progress != nil {
		return s.progress
	}
	return os.Stderr
}

func (s *Source) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	client := s.s3Client()
	s.nextState = &incrementalState{Version: 1, Objects: map[string]objectIncrementalState{}}
	var summary scanSummary
	defer func() {
		fmt.Fprintln(s.progressWriter(), summary.String())
	}()

	jobs := make(chan objectJob, s.concurrency)
	var workers sync.WaitGroup
	var stateMu sync.Mutex
	var coverageMu sync.Mutex
	var coverage []engine.ScanFailure
	coverageTotal := 0
	recordFailure := func(key string, err error) {
		summary.failed.Add(1)
		coverageMu.Lock()
		coverageTotal++
		if len(coverage) < maxCoverageExamples {
			source := "s3-listing"
			if key != "" {
				source = safeObjectLocator(key)
			}
			coverage = append(coverage, engine.ScanFailure{
				Kind:   engine.FailureSource,
				Source: source,
				Err:    err,
			})
		}
		coverageMu.Unlock()
	}
	complete := func(job objectJob) {
		stateMu.Lock()
		s.nextState.Objects[job.key] = job.state
		stateMu.Unlock()
	}
	for range s.concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				outcome, err := s.emitObject(ctx, client, job.key, job.state.Size, ch)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					if errors.Is(err, errArchiveObjectTooLarge) {
						summary.archiveOversize.Add(1)
					}
					recordFailure(job.key, err)
					continue
				}
				if outcome.checkpoint {
					complete(job)
				}
				switch {
				case outcome.empty:
					summary.empty.Add(1)
				case outcome.binary:
					summary.binary.Add(1)
				default:
					summary.scanned.Add(1)
					summary.bytes.Add(outcome.bytes)
				}
			}
		}()
	}
	waitWorkers := func() {
		close(jobs)
		workers.Wait()
	}

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
	}
	if s.prefix != "" {
		input.Prefix = aws.String(s.prefix)
	}

	paginator := s3.NewListObjectsV2Paginator(client, input)
	for paginator.HasMorePages() {
		if err := ctx.Err(); err != nil {
			waitWorkers()
			return err
		}
		page, err := paginator.NextPage(ctx)
		if err != nil {
			recordFailure("", redactCoverageError("list objects", err))
			break
		}
		for _, obj := range page.Contents {
			summary.listed.Add(1)
			if err := ctx.Err(); err != nil {
				waitWorkers()
				return err
			}
			key := aws.ToString(obj.Key)
			if strings.HasSuffix(key, "/") {
				summary.directory.Add(1)
				continue
			}
			if obj.Size != nil && *obj.Size > s.maxSizeBytes {
				summary.oversize.Add(1)
				continue
			}
			if !s.keyAllowed(key) {
				summary.filtered.Add(1)
				continue
			}
			objState := stateForObject(obj)
			if s.objectUnchanged(key, objState) {
				complete(objectJob{key: key, state: objState})
				summary.unchanged.Add(1)
				continue
			}
			if obj.Size != nil && *obj.Size == 0 {
				complete(objectJob{key: key, state: objState})
				summary.empty.Add(1)
				continue
			}
			select {
			case jobs <- objectJob{key: key, state: objState}:
			case <-ctx.Done():
				waitWorkers()
				return ctx.Err()
			}
		}
	}
	waitWorkers()
	if err := ctx.Err(); err != nil {
		return err
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

// ResourceFingerprint deliberately opts out of the whole-source skip. The
// per-object ETag state below already owns incrementality; listing here would
// double the dominant request cost for every changed scan.
func (s *Source) ResourceFingerprint(context.Context) (string, error) {
	return "", nil
}

func (s *Source) emitObject(ctx context.Context, client s3API, key string, sizeHint int64, ch chan<- *sources.Chunk) (objectOutcome, error) {
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if out != nil && out.Body != nil {
			_ = out.Body.Close()
		}
		return objectOutcome{}, redactCoverageError("get object", err)
	}
	if out == nil || out.Body == nil {
		return objectOutcome{}, errors.New("get object returned an empty body")
	}
	defer out.Body.Close()

	limited := io.LimitReader(out.Body, s.maxSizeBytes+1)
	prefix := make([]byte, binarySniffLen)
	n, readErr := io.ReadFull(limited, prefix)
	prefix = prefix[:n]
	if int64(n) > s.maxSizeBytes {
		return objectOutcome{}, fmt.Errorf("object exceeds %d-byte limit while reading", s.maxSizeBytes)
	}
	atEOF := errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF)
	if readErr != nil && !atEOF {
		return objectOutcome{}, redactCoverageError("read object", readErr)
	}
	if len(prefix) == 0 {
		return objectOutcome{empty: true, checkpoint: true}, nil
	}
	if archive.LooksLikeArchive(prefix) {
		// The engine archive API consumes []byte. Keep compressed payloads
		// intact, but honor both the configured object limit and its 50 MiB
		// memory budget. The limit+1 read below detects objects that grew
		// after listing instead of treating the LimitReader EOF as success.
		archiveLimit := min(s.maxSizeBytes, maxArchiveObjectSize)
		if sizeHint > archiveLimit {
			return objectOutcome{}, errArchiveObjectTooLarge
		}
		data, err := readArchiveObject(limited, prefix, sizeHint, archiveLimit)
		if err != nil {
			if errors.Is(err, errArchiveObjectTooLarge) {
				return objectOutcome{}, err
			}
			return objectOutcome{}, redactCoverageError("read archive object", err)
		}
		if err := s.emitChunk(ctx, key, out, data, ch); err != nil {
			return objectOutcome{}, err
		}
		// The CLI persists source state only after engine archive expansion and
		// sink Close both succeed; a degraded/fatal run restores prior state.
		// Marking the emitted object complete here avoids re-downloading every
		// unchanged archive while preserving complete-report retry semantics.
		return objectOutcome{bytes: int64(len(data)), checkpoint: true}, nil
	}
	if isBinary(prefix) {
		return objectOutcome{binary: true, checkpoint: true}, nil
	}
	total, err := s.emitTextObject(ctx, key, out, prefix, limited, atEOF, ch)
	if err != nil {
		return objectOutcome{}, err
	}
	return objectOutcome{bytes: total, checkpoint: true}, nil
}

func readArchiveObject(r io.Reader, prefix []byte, sizeHint, limit int64) ([]byte, error) {
	if limit <= 0 || int64(len(prefix)) > limit {
		return nil, errArchiveObjectTooLarge
	}
	capHint := sizeHint + 1
	if capHint < int64(len(prefix)) {
		capHint = int64(len(prefix))
	}
	if capHint > limit+1 {
		capHint = limit + 1
	}
	data := make([]byte, len(prefix), int(capHint))
	copy(data, prefix)
	for {
		if len(data) == cap(data) {
			if int64(len(data)) >= limit+1 {
				return nil, errArchiveObjectTooLarge
			}
			nextCap := min(limit+1, max(int64(cap(data))*2, int64(cap(data))+32*1024))
			grown := make([]byte, len(data), int(nextCap))
			copy(grown, data)
			data = grown
		}
		n, err := io.ReadFull(r, data[len(data):cap(data)])
		data = data[:len(data)+n]
		if int64(len(data)) > limit {
			return nil, errArchiveObjectTooLarge
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return data, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func (s *Source) emitTextObject(
	ctx context.Context,
	key string,
	out *s3.GetObjectOutput,
	prefix []byte,
	r io.Reader,
	atEOF bool,
	ch chan<- *sources.Chunk,
) (int64, error) {
	total := int64(len(prefix))
	data := make([]byte, len(prefix), objectChunkSize)
	copy(data, prefix)
	freshBytes := len(prefix)
	for {
		if !atEOF {
			n, err := io.ReadFull(r, data[len(data):cap(data)])
			data = data[:len(data)+n]
			total += int64(n)
			freshBytes += n
			if total > s.maxSizeBytes {
				return total, fmt.Errorf("object exceeds %d-byte limit while reading", s.maxSizeBytes)
			}
			atEOF = errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
			if err != nil && !atEOF {
				return total, redactCoverageError("read object", err)
			}
		}
		if atEOF && freshBytes == 0 {
			return total, nil
		}
		if len(data) > 0 {
			if err := s.emitChunk(ctx, key, out, data, ch); err != nil {
				return total, err
			}
		}
		if atEOF {
			return total, nil
		}
		overlap := min(len(data), objectChunkOverlap)
		next := make([]byte, overlap, objectChunkSize)
		copy(next, data[len(data)-overlap:])
		data = next
		freshBytes = 0
	}
}

func (s *Source) emitChunk(
	ctx context.Context,
	key string,
	out *s3.GetObjectOutput,
	data []byte,
	ch chan<- *sources.Chunk,
) error {
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

var _ sources.Source = (*Source)(nil)
var _ sources.ResourceFingerprinter = (*Source)(nil)
var _ sources.IncrementalStateSource = (*Source)(nil)
