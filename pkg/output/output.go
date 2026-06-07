// Package output renders findings in table, JSON, or SARIF form.
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
	case "table":
		return newTableSink(w), nil
	default:
		return nil, fmt.Errorf("output: unknown format %q (valid: json, sarif, table)", format)
	}
}
