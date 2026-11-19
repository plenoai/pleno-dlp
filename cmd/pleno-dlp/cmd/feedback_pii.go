package cmd

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/piiengine/anonymize"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
)

// feedbackLookPath finds the anonymize engine's runtime; tests replace it.
var feedbackLookPath = exec.LookPath

// feedbackStartPII starts the feedback PII pass; tests replace it so they
// never spawn or load a real engine.
var feedbackStartPII = startFeedbackPII

// feedbackPIIEngineMode resolves the feedback --pii-engine value. "auto"
// selects openai-pf-native in an opf_native build, otherwise anonymize when
// its uv runtime is on PATH, otherwise off. explicit reports whether a start
// failure must be fatal rather than a warning.
func feedbackPIIEngineMode(flag string) (mode string, explicit bool, err error) {
	mode = strings.ToLower(strings.TrimSpace(flag))
	switch mode {
	case "", "auto":
		if nativeOPFBuilt {
			return "openai-pf-native", false, nil
		}
		if _, err := feedbackLookPath("uv"); err == nil {
			return "anonymize", false, nil
		}
		return "off", false, nil
	case "off", "anonymize", "openai-pf-native":
		return mode, true, nil
	default:
		return "", false, fmt.Errorf("unknown --pii-engine %q (valid: auto, off, anonymize, openai-pf-native)", flag)
	}
}

// startFeedbackPII starts the selected engine and returns the Redactor PII
// pass plus a stop function. An auto-selected engine that fails to start is
// reported and skipped so feedback still goes out pattern-redacted.
func startFeedbackPII(ctx context.Context, cmd *cobra.Command, stderr io.Writer, flag string) (pass func(context.Context, string) ([]crash.PIIMatch, error), stop func(), err error) {
	mode, explicit, err := feedbackPIIEngineMode(flag)
	if err != nil || mode == "off" {
		return nil, nil, err
	}
	switch mode {
	case "anonymize":
		stop, err = startAnonymize(ctx, cmd, stderr)
	case "openai-pf-native":
		stop, err = startOpenAIPFNative(ctx, cmd, stderr)
	}
	if err != nil {
		if explicit {
			return nil, nil, fmt.Errorf("feedback: start --pii-engine=%s: %w", mode, err)
		}
		fmt.Fprintf(stderr, "feedback: pii-engine %s unavailable (%v); redacting with patterns and detectors only\n", mode, err)
		return nil, nil, nil
	}
	return defaultPIIPass, stop, nil
}

// defaultPIIPass analyzes text with whichever engine is published.
func defaultPIIPass(ctx context.Context, text string) ([]crash.PIIMatch, error) {
	if out, ok, err := nativePIIPass(ctx, text); ok {
		return out, err
	}
	if sup := anonymize.Default(); sup != nil {
		fs, err := sup.Analyze(ctx, text, "")
		out := make([]crash.PIIMatch, 0, len(fs))
		for _, f := range fs {
			out = append(out, crash.PIIMatch{Type: f.EntityType, Text: f.Text})
		}
		return out, err
	}
	return nil, nil
}
