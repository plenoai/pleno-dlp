package cmd

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/piiengine/anonymize"
)

// startPIIEngine evaluates --pii-engine and (when active) spawns the
// configured supervisor, publishes it via anonymize.SetDefault, and
// returns a stop function the caller defers.
//
// Return contract:
//
//   - stop=nil, err=nil  → engine is off (the default), nothing to clean up
//   - stop!=nil, err=nil → engine is up, caller must defer stop()
//   - stop=nil, err!=nil → engine was requested but failed to start; the
//                          caller logs the error and proceeds without PII
//                          detection (the supervisor handle stays nil so
//                          the detector silently no-ops per its contract)
//
// We never propagate spawn failure into the scan exit code: a failed
// PII engine on a noisy laptop should not block a secret scan in CI.
// The detector half of the feature checks anonymize.Default() at the
// top of FromData and returns (nil, nil) when nil, so a missed spawn
// degrades to "no PII findings" rather than a panic.
func startPIIEngine(ctx context.Context, stderr io.Writer) (stop func(), err error) {
	mode := strings.ToLower(strings.TrimSpace(scanOpts.piiEngine))
	switch mode {
	case "", "off":
		// Belt-and-braces: ensure no stale supervisor lingers from a
		// previous in-process invocation (matters for tests that
		// share the cmd package across cases).
		anonymize.SetDefault(nil)
		return nil, nil
	case "anonymize":
		// fall through
	default:
		return nil, fmt.Errorf("unknown --pii-engine %q (valid: off, anonymize)", scanOpts.piiEngine)
	}

	// "auto" is a CLI sentinel meaning "let the engine pick" — translate
	// to empty so the supervisor doesn't ship a literal "auto" over the
	// wire to /api/analyze.
	language := scanOpts.piiEngineLanguage
	if strings.EqualFold(language, "auto") {
		language = ""
	}

	argv, err := splitArgv(scanOpts.piiEngineCmd)
	if err != nil {
		return nil, fmt.Errorf("parse --pii-engine-cmd: %w", err)
	}

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
		// Stop is a safe no-op after a failed Start (it tears down
		// any partial child the spawn may have launched). Calling it
		// here keeps the supervisor in the terminal "stopped" state
		// so the leaked goroutine that would have reaped the child
		// exits cleanly.
		_ = sup.Stop()
		return nil, err
	}
	anonymize.SetDefault(sup)
	fmt.Fprintf(stderr, "pii-engine: anonymize started at %s\n", sup.BaseURL())

	return func() {
		// Reset the handle BEFORE Stop so any in-flight Analyze call
		// sees ErrNotStarted on its next attempt rather than racing
		// the http client's idle-conn close. The supervisor itself
		// already handles concurrent Stop+Analyze safely under -race;
		// resetting first just narrows the window.
		anonymize.SetDefault(nil)
		_ = sup.Stop()
	}, nil
}

// splitArgv splits the user-supplied --pii-engine-cmd into argv tokens.
//
// We keep the parser intentionally simple: whitespace-split with single
// and double quotes preserving spans. This is sufficient for the
// documented Docker default and for the realistic local-checkout cases
// (`uv run --directory /path ...`); operators with truly exotic argv
// shapes can shell out to a wrapper script.
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
