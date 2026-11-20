//go:build !opf_native

package cmd

import (
	"context"
	"io"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
)

// nativeOPFBuilt reports whether this binary includes the in-process
// privacy-filter.cpp engine. False in the default pure-Go build; scan.go's
// preflight reads it to hard-fail --pii-engine=openai-pf-native here rather
// than letting the spawn-failure downgrade swallow it (ADR-0005 §F). The
// opf_native build overrides this to true.
const nativeOPFBuilt = false

func startOpenAIPFNative(_ context.Context, _ *cobra.Command, _ io.Writer) (func(), error) {
	return nil, errNativeNotBuilt
}

// nativePIIPass never finds an engine without the opf_native build tag.
func nativePIIPass(context.Context, string) ([]crash.PIIMatch, bool, error) {
	return nil, false, nil
}
