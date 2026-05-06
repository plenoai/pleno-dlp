// Package output owns the user-visible reporting surface. A Sink consumes
// engine.Finding values and renders them in one of three formats: pretty
// table for humans, JSON array for tooling, SARIF 2.1.0 for code-scanning
// pipelines. New formats land here behind the same factory.
package output

import (
	"fmt"
	"io"

	"github.com/plenoai/pleno-secret-scanner/pkg/engine"
)

// Sink is the output contract. It extends engine.Sink with no extra methods
// today; the alias exists so callers can program against pkg/output without
// pulling pkg/engine for the interface itself.
type Sink interface {
	engine.Sink
}

// NewSink builds a sink for the given format name. Writer w is where the
// rendered output goes (stdout from the CLI). Unknown formats return an
// error rather than silently picking a default — callers must be explicit.
func NewSink(format string, w io.Writer) (Sink, error) {
	switch format {
	case "json":
		return newJSONSink(w), nil
	case "sarif":
		return newSARIFSink(w), nil
	case "table":
		return newTableSink(w), nil
	default:
		return nil, fmt.Errorf("output: unknown format %q (valid: json, sarif, table)", format)
	}
}
