// Package output renders findings in table, JSON, JSON Lines, SARIF, or self-contained HTML form.
package output

import (
	"fmt"
	"io"

	"github.com/plenoai/pleno-dlp/pkg/engine"
)

type Sink interface {
	engine.Sink
}

func NewSink(format string, w io.Writer, version string) (Sink, error) {
	switch format {
	case "json":
		return newJSONSink(w), nil
	case "sarif":
		return newSARIFSink(w, version), nil
	case "jsonl":
		return newJSONLSink(w), nil
	case "html":
		return newHTMLSink(w, version), nil
	case "table":
		return newTableSink(w), nil
	default:
		return nil, fmt.Errorf("output: unknown format %q (valid: %s)", format, FormatsHelp)
	}
}

// Formats lists every format NewSink accepts.
var Formats = []string{"json", "jsonl", "sarif", "html", "table"}

// FormatsHelp is Formats joined for flag help and errors.
const FormatsHelp = "json, jsonl, sarif, html, table"
