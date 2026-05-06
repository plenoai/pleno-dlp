package output

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// SARIF 2.1.0 minimal envelope. We only fill the fields that GitHub code
// scanning actually consumes; richer rule metadata can come later without
// breaking the schema.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

// sarifSink buffers results and writes the full SARIF document on Close.
// Buffering is required because SARIF is a single JSON object, not a stream.
type sarifSink struct {
	w       io.Writer
	mu      sync.Mutex
	results []sarifResult
}

func newSARIFSink(w io.Writer) *sarifSink {
	return &sarifSink{w: w, results: make([]sarifResult, 0, 64)}
}

func (s *sarifSink) Emit(f engine.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.results = append(s.results, toSARIFResult(f))
}

func (s *sarifSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	doc := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "pleno-dlp",
				InformationURI: "https://github.com/plenoai/pleno-dlp",
			}},
			Results: s.results,
		}},
	}
	enc := json.NewEncoder(s.w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func toSARIFResult(f engine.Finding) sarifResult {
	r := sarifResult{
		RuleID:  f.Detector.String(),
		Level:   "error",
		Message: sarifMessage{Text: f.Result.Redacted},
	}
	uri, line := sarifLocationOf(f)
	if uri != "" {
		loc := sarifLocation{PhysicalLocation: sarifPhysicalLocation{
			ArtifactLocation: sarifArtifactLocation{URI: uri},
		}}
		if line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{StartLine: line}
		}
		r.Locations = []sarifLocation{loc}
	}
	return r
}

// sarifLocationOf extracts a (uri, line) pair from chunk metadata. Sources
// that don't have a file-shaped origin (S3, Slack) return their best-effort
// URI and zero line.
func sarifLocationOf(f engine.Finding) (string, int) {
	if f.Chunk == nil {
		return "", 0
	}
	md := f.Chunk.SourceMetadata
	switch {
	case md.Filesystem != nil:
		return md.Filesystem.Path, md.Filesystem.Line
	case md.Git != nil:
		return md.Git.File, md.Git.Line
	case md.GitHub != nil:
		return md.GitHub.File, md.GitHub.Line
	case md.S3 != nil:
		return "s3://" + md.S3.Bucket + "/" + md.S3.Key, 0
	case md.GCS != nil:
		return "gs://" + md.GCS.Bucket + "/" + md.GCS.Object, 0
	case md.Slack != nil:
		return md.Slack.Permalink, 0
	}
	return "", 0
}
