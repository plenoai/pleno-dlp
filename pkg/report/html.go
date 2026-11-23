package report

import (
	_ "embed"
	"html/template"
	"io"
	"net/url"
	"strings"
	"time"
)

//go:embed viewer.html.tmpl
var viewerTemplate string

var tmpl = template.Must(template.New("viewer").Funcs(template.FuncMap{
	"join": strings.Join,
	"short": func(s string) string {
		if len(s) > 12 {
			return s[:12]
		}
		return s
	},
	// safeLink only lets http(s) links through; html/template already
	// neutralizes javascript: URLs, this also drops other schemes.
	"safeLink": func(s string) string {
		u, err := url.Parse(s)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			return ""
		}
		return s
	},
}).Parse(viewerTemplate))

// Meta describes the rendered page.
type Meta struct {
	Title     string
	Generator string
	Generated time.Time
	Reports   []string
}

type pageData struct {
	Meta
	Findings   []Finding
	Total      int
	BySeverity []kv
	ByTool     []kv
}

type kv struct {
	Key   string
	Count int
}

// RenderHTML writes a self-contained HTML page (inline CSS/JS, no network
// fetches) listing the findings. Every value is escaped by html/template and
// findings are expected to be already redacted.
func RenderHTML(w io.Writer, findings []Finding, meta Meta) error {
	if meta.Title == "" {
		meta.Title = "pleno-dlp report"
	}
	if meta.Generated.IsZero() {
		meta.Generated = time.Now().UTC()
	}
	return tmpl.Execute(w, pageData{
		Meta:       meta,
		Findings:   findings,
		Total:      len(findings),
		BySeverity: countBy(findings, func(f Finding) []string { return []string{orUnknown(f.Severity)} }),
		ByTool: countBy(findings, func(f Finding) []string {
			if len(f.Tools) > 0 {
				return f.Tools
			}
			return []string{f.Tool}
		}),
	})
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func countBy(fs []Finding, keys func(Finding) []string) []kv {
	idx := map[string]int{}
	var out []kv
	for _, f := range fs {
		for _, k := range keys(f) {
			i, ok := idx[k]
			if !ok {
				i = len(out)
				idx[k] = i
				out = append(out, kv{Key: k})
			}
			out[i].Count++
		}
	}
	return out
}
