package output

import (
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"html/template"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/engine"
)

//go:embed audit.html.tmpl
var auditTemplate string

var auditTmpl = template.Must(template.New("audit").Funcs(template.FuncMap{
	"rfc3339": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format(time.RFC3339)
	},
}).Parse(auditTemplate))

// AuditMeta is scan metadata rendered by the audit-html format. Callers set
// it through SetAuditMeta before Close; it must not contain credentials
// (record flag names, never values).
type AuditMeta struct {
	Source       string
	Flags        []string
	VerifyMode   string
	Started      time.Time
	Chunks       int64
	Bytes        int64
	CoverageGaps int
}

// AuditMetaSetter is implemented by sinks that render scan metadata.
type AuditMetaSetter interface {
	SetAuditMeta(func(*AuditMeta))
}

type auditRow struct {
	Order     int
	Verdict   string
	Assurance string
	Severity  string
	Detector  string
	Redacted  string
	Hash      string
	Location  string
}

// auditHTMLSink renders a compliance-oriented report: run metadata, a
// verdict summary, and findings ordered verified → indeterminate →
// unverified, then by severity. Only redacted records are retained.
type auditHTMLSink struct {
	w       io.Writer
	version string
	mu      sync.Mutex
	meta    AuditMeta
	rows    []auditRow
	sev     []int
}

func newAuditHTMLSink(w io.Writer, version string) *auditHTMLSink {
	return &auditHTMLSink{w: w, version: version, meta: AuditMeta{Started: time.Now().UTC()}}
}

func (s *auditHTMLSink) SetAuditMeta(fn func(*AuditMeta)) {
	s.mu.Lock()
	fn(&s.meta)
	s.mu.Unlock()
}

func (s *auditHTMLSink) Emit(f engine.Finding) {
	r := toJSONRecord(f)
	row := auditRow{
		Verdict: r.Verdict, Assurance: r.Assurance, Severity: r.Severity,
		Detector: r.Detector, Redacted: r.Redacted, Hash: r.SecretHash, Location: LocationOf(f),
	}
	s.mu.Lock()
	s.rows = append(s.rows, row)
	s.sev = append(s.sev, int(f.Result.Severity))
	s.mu.Unlock()
}

func verdictRank(v string) int {
	switch v {
	case "verified":
		return 0
	case "indeterminate":
		return 1
	}
	return 2
}

type auditPage struct {
	Title, Generator, RunID string
	Meta                    AuditMeta
	Completed               time.Time
	Duration                string
	Total                   int
	ByVerdict               []kv
	Rows                    []auditRow
}

type kv struct {
	Key   string
	Count int
}

func (s *auditHTMLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := make([]int, len(s.rows))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ra, rb := s.rows[idx[a]], s.rows[idx[b]]
		if x, y := verdictRank(ra.Verdict), verdictRank(rb.Verdict); x != y {
			return x < y
		}
		if s.sev[idx[a]] != s.sev[idx[b]] {
			return s.sev[idx[a]] > s.sev[idx[b]]
		}
		if ra.Detector != rb.Detector {
			return ra.Detector < rb.Detector
		}
		return ra.Location < rb.Location
	})
	rows := make([]auditRow, len(idx))
	counts := map[string]int{}
	for i, j := range idx {
		rows[i] = s.rows[j]
		rows[i].Order = i + 1
		counts[rows[i].Verdict]++
	}
	var by []kv
	for _, v := range []string{"verified", "indeterminate", "unverified"} {
		by = append(by, kv{v, counts[v]})
	}
	gen := "pleno-dlp"
	if s.version != "" {
		gen += " " + s.version
	}
	completed := time.Now().UTC()
	var id [16]byte
	_, _ = rand.Read(id[:])
	return auditTmpl.Execute(s.w, auditPage{
		Title: "pleno-dlp audit report", Generator: gen, RunID: hex.EncodeToString(id[:]),
		Meta: s.meta, Completed: completed, Duration: completed.Sub(s.meta.Started).Round(time.Millisecond).String(),
		Total: len(rows), ByVerdict: by, Rows: rows,
	})
}
