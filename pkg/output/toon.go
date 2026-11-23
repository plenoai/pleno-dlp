package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// toonSink renders findings as TOON (Token-Oriented Object Notation): a
// header plus one tabular array, which costs LLM agents far fewer tokens
// than the json record. TOON tabular arrays declare their row count up
// front, so rows (already redacted, small) are buffered until Close.
type toonSink struct {
	mu      sync.Mutex
	w       io.Writer
	version string
	rows    [][]string
}

var toonFields = []string{"detector", "severity", "verdict", "redacted", "location", "fingerprint"}

func newTOONSink(w io.Writer, version string) *toonSink { return &toonSink{w: w, version: version} }

func (s *toonSink) Emit(f engine.Finding) {
	row := []string{
		f.Detector.String(),
		f.Result.Severity.String(),
		f.Result.Verdict().String(),
		f.Result.SafeRedacted(),
		LocationOf(f),
		engine.Fingerprint(f),
	}
	s.mu.Lock()
	s.rows = append(s.rows, row)
	s.mu.Unlock()
}

func (s *toonSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	b.WriteString("schema: pleno-dlp.toon.v1\n")
	b.WriteString("tool: pleno-dlp\n")
	if s.version != "" {
		fmt.Fprintf(&b, "version: %s\n", toonValue(s.version))
	}
	fmt.Fprintf(&b, "findings[%d]{%s}:\n", len(s.rows), strings.Join(toonFields, ","))
	for _, r := range s.rows {
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = toonValue(c)
		}
		b.WriteString("  " + strings.Join(cells, ",") + "\n")
	}
	_, err := io.WriteString(s.w, b.String())
	return err
}

// toonValue quotes a cell when it would otherwise be ambiguous: empty,
// padded, containing a delimiter/structural character or control byte, or
// lexically a literal (true/false/null/number).
func toonValue(v string) string {
	needs := v == "" || strings.TrimSpace(v) != v ||
		strings.ContainsAny(v, ",:\"\\[]{}#\n\r\t") ||
		v == "true" || v == "false" || v == "null" || strings.HasPrefix(v, "-") ||
		json.Valid([]byte(v)) && v[0] >= '0' && v[0] <= '9'
	if !needs {
		for _, r := range v {
			if r < 0x20 || r == 0x7f {
				needs = true
				break
			}
		}
	}
	if !needs {
		return v
	}
	q, _ := json.Marshal(v)
	return string(q)
}
