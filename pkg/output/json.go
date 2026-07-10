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
	Detector string `json:"detector"`
	Verified bool   `json:"verified"`
	// Verdict is the three-valued verification outcome ("verified",
	// "unverified", "indeterminate"). Verified stays for backward
	// compatibility — existing consumers keyed on the boolean keep
	// working — but it cannot distinguish "provider said no" from
	// "verification attempt failed", which is exactly the distinction
	// --only-verified needs (#246). New consumers should read Verdict.
	Verdict           string            `json:"verdict"`
	VerificationError string            `json:"verification_error,omitempty"`
	Redacted          string            `json:"redacted"`
	SecretHash        string            `json:"secret_hash,omitempty"`
	SecretHashV2      string            `json:"secret_hash_v2,omitempty"`
	Source            jsonSource        `json:"source"`
	ExtraData         map[string]string `json:"extra_data,omitempty"`
	// SuppressedBy is present only under --show-suppressed: it names the
	// filter that would otherwise have silently dropped this finding
	// ("placeholder" today; "allowlist" once a CLI flag wires that
	// sink's own audit extension point). Additive field — omitted
	// entirely for every finding that reached this sink normally, so
	// existing consumers parsing the schema are unaffected (issue #290).
	SuppressedBy string `json:"suppressed_by,omitempty"`
}

type jsonSource struct {
	Type     string         `json:"type"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// jsonSink streams findings as one JSON array: each Emit writes its element
// immediately instead of buffering the whole result set. Long org scans emit
// enough findings that a buffered array contributes to OOM; streaming keeps
// the sink O(1) in memory. Emit cannot return an error, so the first write
// failure is latched and surfaced from Close.
type jsonSink struct {
	w   io.Writer
	mu  sync.Mutex
	n   int
	err error
}

func newJSONSink(w io.Writer) *jsonSink {
	return &jsonSink{w: w}
}

func (s *jsonSink) Emit(f engine.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(toJSONRecord(f), "  ", "  ")
	if err != nil {
		if s.err == nil {
			s.err = err
		}
		return
	}
	sep := "[\n  "
	if s.n > 0 {
		sep = ",\n  "
	}
	if _, err := io.WriteString(s.w, sep); err != nil {
		if s.err == nil {
			s.err = err
		}
		return
	}
	if _, err := s.w.Write(data); err != nil {
		if s.err == nil {
			s.err = err
		}
		return
	}
	s.n++
}

func (s *jsonSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tail := "[]\n"
	if s.n > 0 {
		tail = "\n]\n"
	}
	if _, err := io.WriteString(s.w, tail); err != nil && s.err == nil {
		s.err = err
	}
	return s.err
}

func toJSONRecord(f engine.Finding) jsonRecord {
	rec := jsonRecord{
		Detector:     f.Detector.String(),
		Verified:     f.Result.Verified,
		Verdict:      f.Result.Verdict().String(),
		Redacted:     f.Result.Redacted,
		SecretHash:   hashSecret(f.Result.Raw),
		ExtraData:    f.Result.ExtraData,
		SuppressedBy: f.SuppressedBy,
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
		if gh.Visibility != "" {
			md["visibility"] = gh.Visibility
		}
		if gh.Owner != "" {
			md["owner"] = gh.Owner
			md["repo"] = gh.Repo
		}
		if gh.Path != "" {
			md["path"] = gh.Path
		}
		if gh.Entity != "" {
			md["entity"] = gh.Entity
			md["number"] = gh.Number
			md["part"] = gh.Part
		}
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
