package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/piiengine/anonymize"
	"github.com/plenoai/pleno-dlp/pkg/piiengine/openaipf"
)

// Per-engine cobra defaults for --pii-engine-cmd. The single scan
// flag carries one cobra default (the anonymize argv), but the
// effective default must follow whichever engine the operator picked.
// startPIIEngine reads cobra's Flag().Changed to detect whether the
// operator explicitly set the flag, and substitutes the per-engine
// default when they didn't. Listing them as constants keeps the
// "what gets spawned by default" answer reviewable in one place
// next to the dispatch.
const (
	defaultAnonymizeCmd = "pleno-dlp pii-server --port {PORT}"
	defaultOpenAIPFCmd  = "pleno-dlp openai-pf-server --port {PORT}"
)

// startPIIEngine evaluates --pii-engine and (when active) spawns the
// configured supervisor, publishes it via the relevant package's
// SetDefault, and returns a stop function the caller defers.
//
// Return contract:
//
//   - stop=nil, err=nil  → engine is off (the default), nothing to clean up
//   - stop!=nil, err=nil → engine is up, caller must defer stop()
//   - stop=nil, err!=nil → engine was requested but failed to start; the
//     caller logs the error and proceeds without PII
//     detection (the supervisor handle stays nil so
//     the detector silently no-ops per its contract)
//
// We never propagate spawn failure into the scan exit code: a failed
// PII engine on a noisy laptop should not block a secret scan in CI.
// The detector half of each engine checks its own Default() at the
// top of FromData and returns (nil, nil) when nil, so a missed spawn
// degrades to "no PII findings" rather than a panic.
//
// anonymize and openai-pf are mutually exclusive in v1 (ADR-0004 §4);
// the single-valued --pii-engine flag enforces this at parse, so this
// function only ever publishes to one Default() at a time. Belt-and-
// braces: every entry path resets the OTHER engine's Default to nil
// so a previous in-process invocation (matters for tests that share
// the cmd package across cases) can't leak across a re-run.
func startPIIEngine(ctx context.Context, cmd *cobra.Command, stderr io.Writer) (stop func(), err error) {
	mode := strings.ToLower(strings.TrimSpace(scanOpts.piiEngine))
	switch mode {
	case "", "off":
		// Belt-and-braces: ensure no stale supervisor lingers from a
		// previous in-process invocation.
		anonymize.SetDefault(nil)
		openaipf.SetDefault(nil)
		return nil, nil
	case "anonymize":
		return startAnonymize(ctx, cmd, stderr)
	case "openai-pf":
		return startOpenAIPF(ctx, cmd, stderr)
	default:
		return nil, fmt.Errorf("unknown --pii-engine %q (valid: off, anonymize, openai-pf)", scanOpts.piiEngine)
	}
}

// piiEngineCmdValue returns the argv to spawn, applying the per-engine
// default when the operator did not override --pii-engine-cmd.
//
// Implemented by reading cobra's Flag().Changed instead of comparing
// the cobra-bound string to its default: a future change to the cobra
// default would silently break the substitution if we compared
// strings, while Changed() reflects only whether the user typed the
// flag on the command line.
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
// Pre-extracted out of startPIIEngine so the openai-pf arm reads at
// the same indentation level and the two arms diff cleanly (ADR-0004
// §4 — keep the switch explicit even at the cost of some repetition).
func startAnonymize(ctx context.Context, cmd *cobra.Command, stderr io.Writer) (stop func(), err error) {
	// "auto" is a CLI sentinel meaning "let the engine pick" — translate
	// to empty so the supervisor doesn't ship a literal "auto" over
	// the wire to /api/analyze.
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
		// Stop is a safe no-op after a failed Start; calling it here
		// keeps the supervisor in the terminal "stopped" state so the
		// leaked goroutine that would have reaped the child exits
		// cleanly.
		_ = sup.Stop()
		return nil, err
	}
	anonymize.SetDefault(sup)
	fmt.Fprintf(stderr, "pii-engine: anonymize started at %s\n", sup.BaseURL())

	return func() {
		// Reset the handle BEFORE Stop so any in-flight Analyze call
		// sees ErrNotStarted on its next attempt rather than racing
		// the http client's idle-conn close.
		anonymize.SetDefault(nil)
		_ = sup.Stop()
	}, nil
}

// startOpenAIPF spawns and publishes the openai-pf supervisor.
// Parallel structure to startAnonymize; the differences are exactly
// the deltas ADR-0004 §4 enumerates (Device passthrough, no Language,
// longer ReadyTimeout default).
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

// resolveExecutable returns the absolute path of the running pleno-dlp
// binary. We prefer os.Executable (kernel-resolved, immune to PATH
// games and shell aliases) and fall back to os.Args[0] only when the
// stdlib reports an error. The fallback is best-effort — on some
// platforms (chroots, exotic BSDs) the kernel can't introspect the
// caller and the user's argv is the only signal.
//
// Returning the bare string "pleno-dlp" as a final fallback would
// silently shift behavior: the supervisor's exec.Command would do a
// PATH lookup, and a misinstalled CI runner could end up launching
// the wrong binary version. We accept that tradeoff because
// os.Executable failing AND os.Args being empty is already a broken
// invocation; the supervisor's spawn-failure path will surface it.
func resolveExecutable() string {
	if exe, err := os.Executable(); err == nil && exe != "" {
		return exe
	}
	if len(os.Args) > 0 && os.Args[0] != "" {
		return os.Args[0]
	}
	return "pleno-dlp"
}

// splitArgv splits the user-supplied --pii-engine-cmd into argv tokens.
//
// We keep the parser intentionally simple: whitespace-split with single
// and double quotes preserving spans. This is sufficient for the
// documented `pleno-dlp pii-server --port {PORT}` /
// `pleno-dlp openai-pf-server --port {PORT}` defaults and for the
// realistic local-checkout cases (`uv run --directory /path ...`);
// operators with truly exotic argv shapes can shell out to a wrapper
// script.
//
// The tradeoff is conscious: pulling in a full POSIX-shell parser would
// add either a third-party dep (CLAUDE.md forbids it for this branch)
// or a hand-rolled implementation big enough to need its own tests.
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
