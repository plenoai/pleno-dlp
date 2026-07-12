package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/piiengine/anonymize"
	"github.com/plenoai/pleno-dlp/pkg/piiengine/openaipf"
)

// Per-engine defaults for --pii-engine-cmd.
const (
	defaultAnonymizeCmd = "pleno-dlp pii-server --port {PORT}"
	defaultOpenAIPFCmd  = "pleno-dlp openai-pf-server --port {PORT}"
)

// errNativeNotBuilt is returned when --pii-engine=openai-pf-native is
// selected on a binary without the opf_native build tag. Defined here
// (untagged) so scan.go's preflight and the stub both reference one source
// of truth across build modes (ADR-0005 §F).
var errNativeNotBuilt = errors.New(`--pii-engine=openai-pf-native requires a binary built with the 'opf_native'
build tag (in-process privacy-filter.cpp inference). This is the portable
pure-Go build, which does not include it. Get the native build: download
pleno-dlp-opf-native_<os>_<arch> from
https://github.com/plenoai/pleno-dlp/releases, or build locally with
` + "`make opf-native-build`" + `. See docs/adr/0005-native-opf-engine.md.`)

// validPIIEngineMode reports whether mode is a recognized --pii-engine value.
// Callers validate this before scanning so an unknown value (an operator typo
// such as "openai-pf" mistyped, or the upstream name "opf") fails fast as a
// config error. That is deliberately distinct from a runtime spawn failure of
// a *valid* engine, which startPIIEngine's callers downgrade to a warning and
// "continue without PII" — a typo must not silently degrade to a secret-only
// scan while the operator believes PII detection is live.
func validPIIEngineMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "off", "anonymize", "openai-pf", "openai-pf-native":
		return true
	default:
		return false
	}
}

// startPIIEngine evaluates --pii-engine, starts the selected supervisor,
// publishes it via SetDefault, and returns a stop function.
func startPIIEngine(ctx context.Context, cmd *cobra.Command, stderr io.Writer) (stop func(), err error) {
	mode := strings.ToLower(strings.TrimSpace(scanOpts.piiEngine))
	switch mode {
	case "", "off":
		anonymize.SetDefault(nil)
		openaipf.SetDefault(nil)
		return nil, nil
	case "anonymize":
		return startAnonymize(ctx, cmd, stderr)
	case "openai-pf":
		return startOpenAIPF(ctx, cmd, stderr)
	case "openai-pf-native":
		return startOpenAIPFNative(ctx, cmd, stderr)
	default:
		return nil, fmt.Errorf("unknown --pii-engine %q (valid: off, anonymize, openai-pf, openai-pf-native)", scanOpts.piiEngine)
	}
}

// piiEngineCmdValue applies the per-engine default when the flag was not overridden.
func piiEngineCmdValue(cmd *cobra.Command, mode string) string {
	if cmd != nil {
		if f := cmd.Flag("pii-engine-cmd"); f != nil && !f.Changed {
			switch mode {
			case "openai-pf":
				return defaultOpenAIPFCmd
			case "anonymize":
				return defaultAnonymizeCmd
			}
		}
	}
	return scanOpts.piiEngineCmd
}

// startAnonymize spawns and publishes the anonymize supervisor.
func startAnonymize(ctx context.Context, cmd *cobra.Command, stderr io.Writer) (stop func(), err error) {
	language := scanOpts.piiEngineLanguage
	if strings.EqualFold(language, "auto") {
		language = ""
	}

	argv, err := splitArgv(piiEngineCmdValue(cmd, "anonymize"))
	if err != nil {
		return nil, fmt.Errorf("parse --pii-engine-cmd: %w", err)
	}
	if argv[0] == "pleno-dlp" {
		argv[0] = resolveExecutable()
	}

	openaipf.SetDefault(nil)

	sup, err := anonymize.New(anonymize.Config{
		Cmd:            argv,
		Port:           scanOpts.piiEnginePort,
		ReadyTimeout:   scanOpts.piiEngineReady,
		RequestTimeout: scanOpts.piiEngineRequest,
		Language:       language,
		Stderr:         stderr,
	})
	if err != nil {
		return nil, err
	}
	if err := sup.Start(ctx); err != nil {
		_ = sup.Stop()
		return nil, err
	}
	anonymize.SetDefault(sup)
	fmt.Fprintf(stderr, "pii-engine: anonymize started at %s\n", sup.BaseURL())

	return func() {
		anonymize.SetDefault(nil)
		_ = sup.Stop()
	}, nil
}

// startOpenAIPF spawns and publishes the openai-pf supervisor.
func startOpenAIPF(ctx context.Context, cmd *cobra.Command, stderr io.Writer) (stop func(), err error) {
	argv, err := splitArgv(piiEngineCmdValue(cmd, "openai-pf"))
	if err != nil {
		return nil, fmt.Errorf("parse --pii-engine-cmd: %w", err)
	}
	if argv[0] == "pleno-dlp" {
		argv[0] = resolveExecutable()
	}

	anonymize.SetDefault(nil)

	sup, err := openaipf.New(openaipf.Config{
		Cmd:            argv,
		Port:           scanOpts.piiEnginePort,
		Device:         scanOpts.piiEngineDevice,
		ReadyTimeout:   scanOpts.piiEngineReady,
		RequestTimeout: scanOpts.piiEngineRequest,
		Stderr:         stderr,
	})
	if err != nil {
		return nil, err
	}
	if err := sup.Start(ctx); err != nil {
		_ = sup.Stop()
		return nil, err
	}
	openaipf.SetDefault(sup)
	fmt.Fprintf(stderr, "pii-engine: openai-pf started at %s\n", sup.BaseURL())

	return func() {
		openaipf.SetDefault(nil)
		_ = sup.Stop()
	}, nil
}

// resolveExecutable prefers os.Executable and falls back to os.Args[0].
func resolveExecutable() string {
	if exe, err := os.Executable(); err == nil && exe != "" {
		return exe
	}
	if len(os.Args) > 0 && os.Args[0] != "" {
		return os.Args[0]
	}
	return "pleno-dlp"
}

// splitArgv splits --pii-engine-cmd using whitespace plus simple quotes.
func splitArgv(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("--pii-engine-cmd is empty")
	}
	var out []string
	var cur strings.Builder
	var quote rune // 0, '\'', or '"'
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			quote = r
		case r == ' ' || r == '\t':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote in argv")
	}
	flush()
	if len(out) == 0 {
		return nil, fmt.Errorf("--pii-engine-cmd parsed to empty argv")
	}
	return out, nil
}
