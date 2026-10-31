package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/feedback"
	"github.com/plenoai/pleno-dlp/pkg/termsafe"
)

// feedbackGetenv is the environment lookup for the feedback command; tests
// replace it to isolate the config directory and endpoint.
var feedbackGetenv = os.Getenv

// feedbackOpenTTY opens the controlling terminal for the confirmation prompt.
// Reading the confirmation from /dev/tty (not stdin) is what lets
// `feedback --stdin` keep the message on stdin while still asking the
// operator interactively. It is a var so tests can substitute a pipe.
var feedbackOpenTTY = func() (*os.File, error) {
	for _, name := range []string{"/dev/tty", "CONIN$"} {
		if f, err := os.OpenFile(name, os.O_RDWR, 0); err == nil {
			return f, nil
		}
	}
	return nil, errors.New("no controlling terminal")
}

type feedbackFlags struct {
	stdin             bool
	yes               bool
	kind              string
	detector          string
	scanFile          string
	findingHash       string
	piiEngine         string
	piiEngineCmd      string
	piiEnginePort     int
	piiEngineLanguage string
	piiEngineReady    time.Duration
	piiEngineRequest  time.Duration
	piiEngineDevice   string
	piiModel          string
	piiModelPath      string
}

var feedbackOpts feedbackFlags

var feedbackCmd = &cobra.Command{
	Use:   "feedback [message]",
	Short: "Send anonymized feedback to the pleno-dlp maintainers",
	Long: `Send a short message to the pleno-dlp maintainers. The message is redacted
with the same pipeline as crash reports before it leaves the machine, every
sent report is also saved to a local spool, and nothing is uploaded until you
confirm at the terminal (or pass --yes). Feedback ignores the crash opt-in
and is locally limited to five uploads per hour. With no message argument,
the message is read from stdin.

For a false-positive report, scan one file offline and select a match by its
SHA-256 hash from scan JSON output. Only the detector, safe redacted display,
and raw hashes are included in schema v2. The selected fields are shown before confirmation.

PII redaction uses an available or locally cached engine by default. Automatic
selection never downloads a model or installs an engine. If no engine is
available, feedback warns that names and other PII may remain.

  pleno-dlp feedback "scan of a 2 GB monorepo OOMs"
  echo "docs typo in verify-coverage.md" | pleno-dlp feedback --stdin
  # Replace HASH with the selected hash from scan JSON output.
  pleno-dlp feedback --kind false-positive --scan-file .env --detector AWS --finding-hash HASH "fixture matched as a credential"`,
	Args: cobra.ArbitraryArgs,
	RunE: runFeedback,
}

func runFeedback(c *cobra.Command, args []string) error {
	message, err := feedbackMessage(c, args)
	if err != nil {
		return err
	}
	if message == "" {
		return errors.New("feedback: empty message (pass text or use --stdin)")
	}

	var selectedMatch detectors.Result
	hasSelectedMatch := false
	switch feedbackOpts.kind {
	case "feedback":
		if feedbackOpts.detector != "" || feedbackOpts.scanFile != "" || feedbackOpts.findingHash != "" {
			return fmt.Errorf("feedback: finding selection flags require --kind false-positive")
		}
	case "false-positive":
		selectedMatch, err = feedbackScanMatch(c.Context(), feedbackOpts.scanFile, feedbackOpts.detector, feedbackOpts.findingHash)
		if err != nil {
			return err
		}
		hasSelectedMatch = true
	default:
		return fmt.Errorf("feedback: invalid --kind %q (want feedback or false-positive)", feedbackOpts.kind)
	}

	selectedPII, err := feedbackPIISelector(c.Context())
	if err != nil {
		return err
	}
	if selectedPII.Stop != nil {
		defer selectedPII.Stop()
	}
	if strings.EqualFold(strings.TrimSpace(feedbackOpts.piiEngine), "auto") && selectedPII.Detector == nil {
		termsafe.Fprintf(c.ErrOrStderr(), "feedback: PII engine unavailable; names and other PII may remain in the report\n")
	} else if selectedPII.Detector != nil {
		termsafe.Fprintf(c.ErrOrStderr(), "feedback: local PII redaction active (%s)\n", selectedPII.Engine)
	}

	home, _ := os.UserHomeDir()
	red := feedbackRedactor(feedbackGetenv, home)
	message, err = redactFeedbackValue(c.Context(), red, selectedPII.Detector, message)
	if err != nil {
		return err
	}
	if hasSelectedMatch {
		selectedMatch.Redacted, err = redactFeedbackValue(c.Context(), red, selectedPII.Detector, selectedMatch.SafeRedacted())
		if err != nil {
			return err
		}
	}

	var report feedback.Report
	meta := crash.Meta{
		Version: toolVersion,
		Commit:  toolCommit,
		Command: "feedback",
		Flags:   feedbackFlagNames(c),
	}
	if hasSelectedMatch {
		report, err = feedback.BuildWithMatch(message, meta, red, time.Now(), selectedMatch)
		if err != nil {
			return err
		}
	} else {
		report = feedback.Build(message, meta, red, time.Now())
	}

	dir, err := feedback.SpoolDir(feedbackGetenv)
	if err != nil {
		return err
	}
	path, err := feedback.Spool(dir, report)
	if err != nil {
		return fmt.Errorf("feedback: save local copy: %w", err)
	}

	endpoint, err := feedback.Endpoint(feedbackGetenv)
	if err != nil {
		return err
	}

	if !feedbackOpts.yes {
		ok, err := confirmFeedback(c, report, endpoint)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintf(c.ErrOrStderr(), "feedback: not sent; local copy saved to %s\n", path)
			return nil
		}
	}

	root, err := crash.Dir(feedbackGetenv)
	if err != nil {
		return err
	}
	throttle := &crash.Throttle{Dir: root}
	if ok, err := throttle.AllowFeedback(); err != nil {
		fmt.Fprintf(c.ErrOrStderr(), "feedback: local throttle unavailable (%v); sending anyway\n", err)
	} else if !ok {
		return fmt.Errorf("feedback: local rate limit reached (%d per hour); local copy saved to %s", crash.FeedbackSendLimit, path)
	}

	if err := feedback.Send(c.Context(), nil, endpoint, toolVersion, report); err != nil {
		return fmt.Errorf("feedback: send %s: %w (local copy saved to %s)", report.Fingerprint, err, path)
	}
	fmt.Fprintf(c.OutOrStdout(), "sent feedback report %s to %s (saved to %s)\n", report.Fingerprint, endpoint, path)
	return nil
}

func feedbackFlagNames(c *cobra.Command) []string {
	var flags []string
	c.Flags().Visit(func(f *pflag.Flag) { flags = append(flags, f.Name) })
	sort.Strings(flags)
	return flags
}

// feedbackMessage reads stdin when requested or when no message was given.
func feedbackMessage(c *cobra.Command, args []string) (string, error) {
	if feedbackOpts.stdin || len(args) == 0 {
		if len(args) > 0 {
			return "", errors.New("feedback: --stdin cannot be combined with a positional message")
		}
		const maxFeedbackBytes = 64 << 10
		b, err := io.ReadAll(io.LimitReader(c.InOrStdin(), maxFeedbackBytes+1))
		if err != nil {
			return "", fmt.Errorf("feedback: read message from stdin: %w", err)
		}
		if len(b) > maxFeedbackBytes {
			return "", fmt.Errorf("feedback: message exceeds %d bytes", maxFeedbackBytes)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return strings.TrimSpace(strings.Join(args, " ")), nil
}

// confirmFeedback asks the operator to approve the send. The question is read
// from /dev/tty so a piped message on stdin does not consume the answer; when
// there is no controlling terminal it falls back to an interactive stdin, and
// otherwise refuses so a non-interactive run must opt in explicitly with
// --yes.
func confirmFeedback(c *cobra.Command, report feedback.Report, endpoint string) (bool, error) {
	var in io.Reader
	if tty, err := feedbackOpenTTY(); err == nil {
		defer tty.Close()
		in = tty
	} else if isInteractiveStdin(c.InOrStdin()) {
		in = c.InOrStdin()
	} else {
		return false, errors.New("feedback: no terminal for confirmation; re-run with --yes to send")
	}
	fmt.Fprintf(c.ErrOrStderr(), "%s\n", report.Message)
	if report.Match != nil {
		fmt.Fprintf(c.ErrOrStderr(), "\nSelected finding:\n  detector: %s\n  redacted: %s\n  raw hash: %s\n",
			termsafe.String(report.Match.Detector), termsafe.String(report.Match.Redacted), report.Match.RawHash)
		if report.Match.RawV2Hash != "" {
			fmt.Fprintf(c.ErrOrStderr(), "  raw v2 hash: %s\n", report.Match.RawV2Hash)
		}
	}
	fmt.Fprintf(c.ErrOrStderr(), "\nSend this feedback report to %s? [y/N] ", endpoint)
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func init() {
	feedbackCmd.Flags().BoolVar(&feedbackOpts.stdin, "stdin", false, "read the feedback message from stdin instead of arguments")
	feedbackCmd.Flags().BoolVarP(&feedbackOpts.yes, "yes", "y", false, "skip the interactive confirmation prompt and send immediately")
	feedbackCmd.Flags().StringVar(&feedbackOpts.kind, "kind", "feedback", "report kind: feedback or false-positive")
	feedbackCmd.Flags().StringVar(&feedbackOpts.detector, "detector", "", "require the selected finding to use this detector")
	feedbackCmd.Flags().StringVar(&feedbackOpts.scanFile, "scan-file", "", "file to scan offline for a false-positive report")
	feedbackCmd.Flags().StringVar(&feedbackOpts.findingHash, "finding-hash", "", "64-character secret_hash or secret_hash_v2 from scan JSON output")
	feedbackCmd.Flags().StringVar(&feedbackOpts.piiEngine, "pii-engine", "auto", "PII redaction engine: auto, off, anonymize, or openai-pf-native")
	feedbackCmd.Flags().StringVar(&feedbackOpts.piiEngineCmd, "pii-engine-cmd", defaultAnonymizeCmd, "argv to spawn the anonymize engine when explicitly selected")
	feedbackCmd.Flags().IntVar(&feedbackOpts.piiEnginePort, "pii-engine-port", 0, "loopback port for the anonymize engine (0 = auto-allocate)")
	feedbackCmd.Flags().StringVar(&feedbackOpts.piiEngineLanguage, "pii-engine-language", "auto", "language hint passed to the anonymize engine: ja, en, or auto")
	feedbackCmd.Flags().DurationVar(&feedbackOpts.piiEngineReady, "pii-engine-ready-timeout", 0, "time to wait for the PII engine to become ready (0 defaults to 60s)")
	feedbackCmd.Flags().DurationVar(&feedbackOpts.piiEngineRequest, "pii-engine-request-timeout", 10*time.Second, "per-request timeout for anonymize; feedback rejects results returned after 2s per text field (synchronous inference may continue)")
	feedbackCmd.Flags().StringVar(&feedbackOpts.piiEngineDevice, "pii-engine-device", "auto", "inference device for openai-pf-native: auto, cpu, cuda, or mps")
	feedbackCmd.Flags().StringVar(&feedbackOpts.piiModel, "pii-model", "q8", "GGUF model variant for openai-pf-native: q8 or f16")
	feedbackCmd.Flags().StringVar(&feedbackOpts.piiModelPath, "pii-model-path", "", "explicit local GGUF path for openai-pf-native")
	Root.AddCommand(feedbackCmd)
}
