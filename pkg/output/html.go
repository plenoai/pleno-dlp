package output

import (
	"io"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/report"
)

// htmlSink buffers redacted findings and renders one self-contained HTML
// page on Close. Only the redacted record (never Result.Raw/RawV2) is
// retained, so the buffer holds no secret material.
type htmlSink struct {
	w       io.Writer
	version string
	mu      sync.Mutex
	recs    []report.Finding
}

func newHTMLSink(w io.Writer, version string) *htmlSink {
	return &htmlSink{w: w, version: version}
}

func (s *htmlSink) Emit(f engine.Finding) {
	rec := toReportFinding(toJSONRecord(f))
	s.mu.Lock()
	s.recs = append(s.recs, rec)
	s.mu.Unlock()
}

func (s *htmlSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	gen := "pleno-dlp"
	if s.version != "" {
		gen += " " + s.version
	}
	return report.RenderHTML(s.w, report.Merge(s.recs), report.Meta{Generator: gen})
}

func toReportFinding(r jsonRecord) report.Finding {
	md := r.Source.Metadata
	str := func(k string) string { v, _ := md[k].(string); return v }
	line, _ := md["line"].(int)
	file := str("file")
	for _, k := range []string{"path", "key", "object", "label"} {
		if file == "" {
			file = str(k)
		}
	}
	return report.Finding{
		Tool:       "pleno-dlp",
		Detector:   r.Detector,
		Severity:   r.Severity,
		Verdict:    r.Verdict,
		Redacted:   r.Redacted,
		SecretHash: r.SecretHash,
		SourceType: r.Source.Type,
		Repository: str("repository"),
		Commit:     str("commit"),
		File:       file,
		Line:       line,
		Link:       str("link"),
	}
}
