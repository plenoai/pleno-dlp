//go:build opf_native

package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/piiengine/anonymize"
	"github.com/plenoai/pleno-dlp/pkg/piiengine/opfnative"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
)

const nativeOPFBuilt = true

// startOpenAIPFNative resolves the GGUF, loads the in-process engine, and
// publishes it. Model-resolution / pf_load failures return an error, which
// runScanCommon downgrades to "continue without PII" — consistent with the
// other engines' runtime failures. The "not built" case never reaches here
// (this file exists only in the tagged build); scan.go's preflight handles
// it against the stub's nativeOPFBuilt=false.
func startOpenAIPFNative(ctx context.Context, _ *cobra.Command, stderr io.Writer) (func(), error) {
	path, err := opfnative.ResolveModelPath(ctx, scanOpts.piiModel, scanOpts.piiModelPath, stderr)
	if err != nil {
		return nil, err
	}
	eng, err := opfnative.New(opfnative.Config{
		ModelPath: path,
		Device:    scanOpts.piiEngineDevice,
	})
	if err != nil {
		return nil, err
	}

	anonymize.SetDefault(nil)
	opfnative.SetDefault(eng)
	fmt.Fprintf(stderr, "pii-engine: openai-pf-native loaded %s\n", path)

	return func() {
		opfnative.SetDefault(nil)
		_ = eng.Close()
	}, nil
}

// nativePIIPass analyzes text with the published native engine; ok is false
// when none is published.
func nativePIIPass(ctx context.Context, text string) (out []crash.PIIMatch, ok bool, err error) {
	eng := opfnative.Default()
	if eng == nil {
		return nil, false, nil
	}
	fs, err := eng.Analyze(ctx, text)
	for _, f := range fs {
		out = append(out, crash.PIIMatch{Type: f.EntityType, Text: f.Text})
	}
	return out, true, err
}
