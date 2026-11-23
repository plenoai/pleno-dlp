package s3

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	"github.com/plenoai/pleno-dlp/pkg/sources/volumeset"
)

// volumeSets collects multi-volume archive keys during listing.
type volumeSets struct {
	sets *volumeset.Sets[objectIncrementalState]
}

func newVolumeSets() *volumeSets {
	return &volumeSets{sets: volumeset.New[objectIncrementalState]()}
}

// add records key when it names an archive volume.
func (v *volumeSets) add(key string, state objectIncrementalState) bool {
	return v.sets.Add(key, state.Size, state)
}

// jobs returns one job per linked set and a plain job for every other
// volume key.
func (v *volumeSets) jobs(maxTotal int64) []objectJob {
	var out []objectJob
	for _, j := range v.sets.Jobs(maxTotal) {
		job := objectJob{key: j.Head.Key, state: j.Head.Item, scheme: j.Scheme}
		for _, m := range j.Volumes {
			job.volumes = append(job.volumes, objectJob{key: m.Key, state: m.Item})
		}
		out = append(out, job)
	}
	return out
}

func allUnchanged(s *Source, jobs []objectJob) bool {
	for _, j := range jobs {
		if !s.objectUnchanged(j.key, j.state) {
			return false
		}
	}
	return true
}

// emitVolumes downloads every volume, joins them, and emits one archive
// chunk located at volume 1. Volumes that do not link (an EGG split chain
// that breaks) are scanned on their own.
func (s *Source) emitVolumes(ctx context.Context, client s3API, job objectJob, ch chan<- *sources.Chunk) (objectOutcome, error) {
	limit := min(s.maxSizeBytes, maxArchiveObjectSize)
	all := append([]objectJob{{key: job.key, state: job.state}}, job.volumes...)
	vols := make([]archive.Volume, 0, len(all))
	var first *s3.GetObjectOutput
	remaining := limit
	for _, v := range all {
		out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(v.key)})
		if err != nil {
			if out != nil && out.Body != nil {
				_ = out.Body.Close()
			}
			return objectOutcome{}, redactCoverageError("get object", err)
		}
		if out == nil || out.Body == nil {
			return objectOutcome{}, errors.New("get object returned an empty body")
		}
		data, err := io.ReadAll(io.LimitReader(out.Body, remaining+1))
		_ = out.Body.Close()
		if err != nil {
			return objectOutcome{}, redactCoverageError("read archive object", err)
		}
		if int64(len(data)) > remaining {
			return objectOutcome{}, errArchiveObjectTooLarge
		}
		remaining -= int64(len(data))
		if first == nil {
			first = out
		}
		vols = append(vols, archive.Volume{R: bytes.NewReader(data), Size: int64(len(data))})
	}
	r, size, count, err := archive.JoinVolumes(job.scheme, vols, limit)
	if err != nil {
		count = 0
	}
	var total int64
	if count >= 2 {
		joined := make([]byte, size)
		if _, err := r.ReadAt(joined, 0); err != nil {
			return objectOutcome{}, err
		}
		if err := s.emitChunk(ctx, job.key, first, joined, ch); err != nil {
			return objectOutcome{}, err
		}
		total = size
	} else {
		count = 0
	}
	for _, v := range all[count:] {
		outcome, err := s.emitObject(ctx, client, v.key, v.state.Size, ch)
		if err != nil {
			return objectOutcome{}, err
		}
		total += outcome.bytes
	}
	return objectOutcome{bytes: total, checkpoint: true}, nil
}
