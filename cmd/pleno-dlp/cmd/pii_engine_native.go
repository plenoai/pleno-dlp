//go:build opf_native

package cmd

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	pfdet "github.com/plenoai/pleno-dlp/pkg/detectors/openaipf"
	"github.com/plenoai/pleno-dlp/pkg/piiengine/anonymize"
	"github.com/plenoai/pleno-dlp/pkg/piiengine/openaipf"
	"github.com/plenoai/pleno-dlp/pkg/piiengine/opfnative"
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
	openaipf.SetDefault(nil)
	opfnative.SetDefault(eng)
	pfdet.SetEngineImplNative()
	fmt.Fprintf(stderr, "pii-engine: openai-pf-native loaded %s\n", path)

	return func() {
		opfnative.SetDefault(nil)
		_ = eng.Close()
	}, nil
}
