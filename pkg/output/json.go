package output

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// jsonRecord is the wire shape for one finding. Keep field names stable —
// pkg/output schema is SemVer-managed and breaking changes here require a
// major bump tracked in _workspace/breaking-changes.md.
type jsonRecord struct {
	Detector          string            `json:"detector"`
	Verified          bool              `json:"verified"`
	VerificationError string            `json:"verification_error,omitempty"`
	Redacted          string            `json:"redacted"`
	Source            jsonSource        `json:"source"`
	ExtraData         map[string]string `json:"extra_data,omitempty"`
}

type jsonSource struct {
	Type     string         `json:"type"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// jsonSink buffers findings and writes a single indented JSON array on
// Close. We deliberately avoid NDJSON: the array form is friendlier to
// `jq` and the buffering cost is bounded by dedup upstream.
type jsonSink struct {
	w   io.Writer
	mu  sync.Mutex
	buf []jsonRecord
}

func newJSONSink(w io.Writer) *jsonSink {
	return &jsonSink{w: w, buf: make([]jsonRecord, 0, 64)}
}

func (s *jsonSink) Emit(f engine.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, toJSONRecord(f))
}

func (s *jsonSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	enc := json.NewEncoder(s.w)
	enc.SetIndent("", "  ")
	// Encode the slice itself so the output is always a JSON array, even
	// when zero findings — downstream consumers rely on `[]` not `null`.
	return enc.Encode(s.buf)
}

func toJSONRecord(f engine.Finding) jsonRecord {
	rec := jsonRecord{
		Detector:  f.Detector.String(),
		Verified:  f.Result.Verified,
		Redacted:  f.Result.Redacted,
		ExtraData: f.Result.ExtraData,
	}
	if f.Result.VerificationErr != nil {
		rec.VerificationError = f.Result.VerificationErr.Error()
	}
	rec.Source = jsonSourceOf(f.Chunk)
	return rec
}

func jsonSourceOf(c *sources.Chunk) jsonSource {
	out := jsonSource{Type: "unknown"}
	if c == nil {
		return out
	}
	out.Type = c.SourceType.String()
	md := map[string]any{}
	switch {
	case c.SourceMetadata.Filesystem != nil:
		md["path"] = c.SourceMetadata.Filesystem.Path
		md["line"] = c.SourceMetadata.Filesystem.Line
	case c.SourceMetadata.Git != nil:
		g := c.SourceMetadata.Git
		md["repository"] = g.Repository
		md["commit"] = g.Commit
		md["file"] = g.File
		md["line"] = g.Line
	case c.SourceMetadata.GitHub != nil:
		gh := c.SourceMetadata.GitHub
		md["repository"] = gh.Repository
		md["commit"] = gh.Commit
		md["file"] = gh.File
		md["line"] = gh.Line
	case c.SourceMetadata.S3 != nil:
		md["bucket"] = c.SourceMetadata.S3.Bucket
		md["key"] = c.SourceMetadata.S3.Key
	case c.SourceMetadata.GCS != nil:
		md["bucket"] = c.SourceMetadata.GCS.Bucket
		md["object"] = c.SourceMetadata.GCS.Object
	case c.SourceMetadata.Slack != nil:
		md["channel"] = c.SourceMetadata.Slack.Channel
		md["timestamp"] = c.SourceMetadata.Slack.Timestamp
	case c.SourceMetadata.Stdin != nil:
		md["label"] = c.SourceMetadata.Stdin.Label
	}
	if len(md) > 0 {
		out.Metadata = md
	}
	return out
}
