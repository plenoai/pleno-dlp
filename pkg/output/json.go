package output

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// jsonRecord is the wire shape for one finding.
type jsonRecord struct {
	Detector          string            `json:"detector"`
	Verified          bool              `json:"verified"`
	VerificationError string            `json:"verification_error,omitempty"`
	Redacted          string            `json:"redacted"`
	SecretHash        string            `json:"secret_hash,omitempty"`
	SecretHashV2      string            `json:"secret_hash_v2,omitempty"`
	Source            jsonSource        `json:"source"`
	ExtraData         map[string]string `json:"extra_data,omitempty"`
}

type jsonSource struct {
	Type     string         `json:"type"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// jsonSink buffers findings and writes a single JSON array on Close.
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
	return enc.Encode(s.buf)
}

func toJSONRecord(f engine.Finding) jsonRecord {
	rec := jsonRecord{
		Detector:   f.Detector.String(),
		Verified:   f.Result.Verified,
		Redacted:   f.Result.Redacted,
		SecretHash: hashSecret(f.Result.Raw),
		ExtraData:  f.Result.ExtraData,
	}
	rec.SecretHashV2 = hashSecret(f.Result.RawV2)
	if f.Result.VerificationErr != nil {
		rec.VerificationError = f.Result.VerificationErr.Error()
	}
	rec.Source = jsonSourceOf(f.Chunk)
	return rec
}

func hashSecret(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
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
		if g.Author != "" {
			md["author"] = g.Author
		}
		if g.Email != "" {
			md["email"] = g.Email
		}
		if g.AuthoredDate != "" {
			md["authored_date"] = g.AuthoredDate
		}
		if g.Message != "" {
			md["message"] = g.Message
		}
	case c.SourceMetadata.GitHub != nil:
		gh := c.SourceMetadata.GitHub
		md["repository"] = gh.Repository
		md["link"] = gh.Link
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
	case c.SourceMetadata.Forge != nil:
		f := c.SourceMetadata.Forge
		md["provider"] = f.Provider
		md["repository"] = f.Repository
		md["branch"] = f.Branch
		md["commit"] = f.Commit
		md["file"] = f.File
		md["line"] = f.Line
	case c.SourceMetadata.SIEM != nil:
		s := c.SourceMetadata.SIEM
		md["provider"] = s.Provider
		md["host"] = s.Host
		md["index"] = s.Index
		md["event_id"] = s.EventID
		md["timestamp"] = s.Timestamp
		md["link"] = s.Link
	case c.SourceMetadata.SQLDump != nil:
		d := c.SourceMetadata.SQLDump
		md["file"] = d.File
		md["database"] = d.Database
		md["table"] = d.Table
		md["line"] = d.Line
		md["format"] = d.Format
	}
	if len(md) > 0 {
		out.Metadata = md
	}
	return out
}
