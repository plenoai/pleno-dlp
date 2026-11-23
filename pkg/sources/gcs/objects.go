package gcs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"google.golang.org/api/iterator"

	"github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	"github.com/plenoai/pleno-dlp/pkg/sources/volumeset"
)

var errArchiveObjectTooLarge = errors.New("archive object exceeds compressed size limit")

// objectInfo is one listed object.
type objectInfo struct {
	Name       string
	Generation int64
	State      objectIncrementalState
}

// bucketAPI is the subset of the GCS bucket the source needs; tests supply
// an in-memory fake.
type bucketAPI interface {
	List(ctx context.Context, prefix string, fn func(objectInfo) error) error
	Open(ctx context.Context, name string, generation int64) (io.ReadCloser, error)
}

type storageBucket struct{ bkt *storage.BucketHandle }

func (b storageBucket) List(ctx context.Context, prefix string, fn func(objectInfo) error) error {
	query := &storage.Query{}
	if prefix != "" {
		query.Prefix = prefix
	}
	it := b.bkt.Objects(ctx, query)
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := fn(objectInfo{Name: attrs.Name, Generation: attrs.Generation, State: stateForAttrs(attrs)}); err != nil {
			return err
		}
	}
}

func (b storageBucket) Open(ctx context.Context, name string, generation int64) (io.ReadCloser, error) {
	return b.bkt.Object(name).Generation(generation).NewReader(ctx)
}

// redactedCoverageError keeps object names and provider error text, which
// may echo object names, out of coverage diagnostics.
type redactedCoverageError struct {
	operation string
	cause     error
}

func (e *redactedCoverageError) Error() string { return e.operation + " failed" }
func (e *redactedCoverageError) Unwrap() error { return e.cause }

func redactCoverageError(operation string, cause error) error {
	return &redactedCoverageError{operation: operation, cause: cause}
}

// safeObjectLocator must match the engine's archiveFailureSource for GCS.
func safeObjectLocator(name string) string {
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("gcs-object-sha256:%x", sum)
}

// readObject downloads o and returns its bytes, failing instead of
// truncating when the object exceeds limit (it may have grown since
// listing).
func readObject(ctx context.Context, bkt bucketAPI, o objectInfo, limit int64) ([]byte, error) {
	r, err := bkt.Open(ctx, o.Name, o.Generation)
	if err != nil {
		return nil, redactCoverageError("open object", err)
	}
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, redactCoverageError("read object", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("object exceeds %d-byte limit while reading", limit)
	}
	return data, nil
}

// emitObject emits one object: archives whole (the engine expands them
// under its archive budgets and reports coverage gaps), text as-is, and
// binary non-archives not at all.
func (s *Source) emitObject(ctx context.Context, bkt bucketAPI, o objectInfo, ch chan<- *sources.Chunk) error {
	data, err := readObject(ctx, bkt, o, s.maxSizeBytes)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	prefix := data[:min(len(data), binarySniffLen)]
	if archive.LooksLikeArchive(prefix) {
		if int64(len(data)) > s.archiveLimit() {
			return errArchiveObjectTooLarge
		}
		return s.emitChunk(ctx, o, data, ch)
	}
	// An orphan volume of an unlinked multi-volume set still reaches the
	// engine, which reports the split-volume gap and scans the raw bytes.
	if isBinary(prefix) && !archive.OrphanVolumeName(o.Name) {
		return nil
	}
	return s.emitChunk(ctx, o, data, ch)
}

// emitVolumes downloads every volume of a linked set, joins them, and
// emits one archive chunk located at volume 1. Volumes past a broken EGG
// split chain are emitted on their own.
func (s *Source) emitVolumes(ctx context.Context, bkt bucketAPI, job volumeset.Job[objectInfo], ch chan<- *sources.Chunk) error {
	limit := s.archiveLimit()
	all := job.All()
	vols := make([]archive.Volume, 0, len(all))
	remaining := limit
	for _, m := range all {
		data, err := readObject(ctx, bkt, m.Item, remaining)
		if err != nil {
			if !errors.As(err, new(*redactedCoverageError)) {
				return errArchiveObjectTooLarge
			}
			return err
		}
		remaining -= int64(len(data))
		vols = append(vols, archive.Volume{R: bytes.NewReader(data), Size: int64(len(data))})
	}
	r, size, count, err := archive.JoinVolumes(job.Scheme, vols, limit)
	if err != nil || count < 2 {
		count = 0
	} else {
		joined := make([]byte, size)
		if _, err := r.ReadAt(joined, 0); err != nil {
			return err
		}
		if err := s.emitChunk(ctx, job.Head.Item, joined, ch); err != nil {
			return err
		}
	}
	for _, m := range all[count:] {
		if err := s.emitObject(ctx, bkt, m.Item, ch); err != nil {
			return err
		}
	}
	return nil
}

func (s *Source) emitChunk(ctx context.Context, o objectInfo, data []byte, ch chan<- *sources.Chunk) error {
	chunk := &sources.Chunk{
		SourceID:   s.sourceID,
		SourceType: sources.SourceGCS,
		SourceName: s.name,
		Data:       data,
		SourceMetadata: sources.Metadata{
			GCS: &sources.GCSMeta{Bucket: s.bucket, Object: o.Name, Generation: o.Generation},
		},
	}
	select {
	case ch <- chunk:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
