// Package htmlreport renders access maps as a self-contained HTML page
// (kingfisher --view-report equivalent). Every value is escaped by
// html/template; access maps never contain raw secrets, and finding labels
// are taken from already-redacted scan output.
package htmlreport

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"sort"

	"github.com/plenoai/pleno-dlp/pkg/blastradius"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

//go:embed report.html.tmpl
var tmplText string

var tmpl = template.Must(template.New("r").Parse(tmplText))

// Entry is one mapped credential.
type Entry struct {
	Label string // redacted finding label (detector, redacted value, location)
	Map   detectors.AccessMap
}

// Render writes the page; privileged maps sort first.
func Render(w io.Writer, entries []Entry, version string) error {
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Map.Privileged && !entries[j].Map.Privileged })
	priv := 0
	for _, e := range entries {
		if e.Map.Privileged {
			priv++
		}
	}
	return tmpl.Execute(w, map[string]any{"Entries": entries, "Privileged": priv, "Version": version})
}

// FromScan extracts access maps attached by `scan --blast-radius` from a
// pleno-dlp JSON array or JSONL report.
func FromScan(data []byte) ([]Entry, error) {
	type rec struct {
		Detector  string            `json:"detector"`
		Redacted  string            `json:"redacted"`
		ExtraData map[string]string `json:"extra_data"`
		Source    struct {
			Metadata map[string]any `json:"metadata"`
		} `json:"source"`
	}
	var recs []rec
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &recs); err != nil {
			return nil, fmt.Errorf("decode report: %w", err)
		}
	} else {
		sc := bufio.NewScanner(bytes.NewReader(trimmed))
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 || line[0] != '{' {
				continue
			}
			var r rec
			if err := json.Unmarshal(line, &r); err != nil {
				return nil, fmt.Errorf("decode report line: %w", err)
			}
			recs = append(recs, r)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	var out []Entry
	for _, r := range recs {
		raw := r.ExtraData[blastradius.ExtraDataKey]
		if raw == "" {
			continue
		}
		var am detectors.AccessMap
		if err := json.Unmarshal([]byte(raw), &am); err != nil {
			continue
		}
		label := r.Detector + " " + r.Redacted
		if f, ok := r.Source.Metadata["file"].(string); ok && f != "" {
			label += " — " + f
		}
		out = append(out, Entry{Label: label, Map: am})
	}
	return out, nil
}
