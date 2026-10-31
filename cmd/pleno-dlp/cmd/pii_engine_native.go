//go:build opf_native

package cmd

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/piiengine/anonymize"
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
	return startOpenAIPFNativeWithSettings(ctx, scanPIIEngineSettings(nil), stderr)
}

func startOpenAIPFNativeWithSettings(ctx context.Context, settings piiEngineSettings, stderr io.Writer) (func(), error) {
	path, err := opfnative.ResolveModelPath(ctx, settings.model, settings.modelPath, stderr)
	if err != nil {
		return nil, err
	}
	eng, err := opfnative.New(opfnative.Config{
		ModelPath: path,
		Device:    settings.device,
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

func cachedOpenAIPFModelPath(settings piiEngineSettings) (string, bool, error) {
	if settings.modelPath != "" {
		info, err := os.Stat(settings.modelPath)
		if err != nil {
			return "", false, err
		}
		if !info.Mode().IsRegular() {
			return "", false, fmt.Errorf("openai-pf-native model path is not a regular file")
		}
		return settings.modelPath, true, nil
	}
	return opfnative.CachedModelPath(settings.model)
}

func feedbackOpenAIPFActive() bool { return opfnative.Default() != nil }

func clearOpenAIPFNative() { opfnative.SetDefault(nil) }
