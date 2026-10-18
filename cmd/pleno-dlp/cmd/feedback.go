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
	"github.com/plenoai/pleno-dlp/pkg/telemetry/report"
)

// maxFeedbackInput bounds what --file and --stdin read; the message itself
// is capped at report.MaxMessageBytes after redaction.
const maxFeedbackInput = 64 << 10

// feedbackInteractive reports whether the confirmation prompt can be shown;
// tests replace it because they never run on a terminal.
var feedbackInteractive = isInteractiveStdin

// feedbackNow stamps created_at; tests pin it.
var feedbackNow = time.Now

var feedbackOpts struct {
	kind     string
	detector string
	file     string
	stdin    bool
	dryRun   bool
	yes      bool
}

var feedbackCmd = &cobra.Command{
	Use:   "feedback [message...]",
	Short: "Send anonymized feedback or a false-positive report",
	Long: `Feedback builds a report with the same build and platform metadata as a
crash report, redacts the message (paths, emails, IPs, URLs, tokens, and
anything a built-in secret detector matches), prints the exact payload, and
asks before sending it. Running this command is the consent: it does not
require 'telemetry enable', but it does honour the configured endpoint.

Reports land in a private intake repository that only pleno-dlp maintainers
can read. See docs/telemetry.md.`,
	Example: `  pleno-dlp feedback "the SARIF output is missing rule help text"
  pleno-dlp feedback --kind false-positive --detector AWS "matches AKIAIOSFODNN7EXAMPLE in docs"
  pleno-dlp feedback --file notes.txt --dry-run`,
	RunE: runFeedback,
}

func init() {
	f := feedbackCmd.Flags()
	f.StringVar(&feedbackOpts.kind, "kind", string(report.KindFeedback), "report kind: feedback or false-positive")
	f.StringVar(&feedbackOpts.detector, "detector", "", "detector Type name as shown by 'detectors list' (required for --kind false-positive)")
	f.StringVar(&feedbackOpts.file, "file", "", "read the message from this file")
	f.BoolVar(&feedbackOpts.stdin, "stdin", false, "read the message from stdin (requires --yes)")
	f.BoolVar(&feedbackOpts.dryRun, "dry-run", false, "print the exact redacted report to stdout and exit without sending")
	f.BoolVar(&feedbackOpts.yes, "yes", false, "send without the confirmation prompt")
	Root.AddCommand(feedbackCmd)
}

func runFeedback(c *cobra.Command, args []string) error {
	kind := report.Kind(feedbackOpts.kind)
	if kind != report.KindFeedback && kind != report.KindFalsePositive {
		return fmt.Errorf("--kind %q: want feedback or false-positive", feedbackOpts.kind)
	}
	if err := checkFeedbackDetector(kind, feedbackOpts.detector); err != nil {
		return err
	}
	msg, err := feedbackMessage(c, args)
	if err != nil {
		return err
	}
	cfg, err := report.Load(telemetryGetenv)
	if err != nil {
		return err
	}
	meta := report.Meta{Version: toolVersion, Commit: toolCommit, Command: "feedback", Flags: changedFlagNames(c)}
	r, err := report.BuildUser(kind, msg, feedbackOpts.detector, meta, feedbackRedactor(), feedbackNow())
	if err != nil {
		if r.Message == "" {
			return errors.New("message is empty after redaction; nothing to send")
		}
		return err
	}
	payload, err := report.Marshal(r)
	if err != nil {
		return err
	}
	if feedbackOpts.dryRun {
		_, err := c.OutOrStdout().Write(payload)
		return err
	}
	stderr := c.ErrOrStderr()
	fmt.Fprintf(stderr, "pleno-dlp will send this anonymized report to %s:\n%s", cfg.Endpoint, payload)
	if !feedbackOpts.yes {
		ok, err := confirmFeedback(c)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Fprintln(stderr, "not sent")
			return nil
		}
	}
	rc, sendErr := report.Send(c.Context(), nil, cfg.Endpoint, toolVersion, r)
	if sendErr == nil {
		printSent(c, r.Kind, cfg.Endpoint, rc)
		return nil
	}
	path, err := report.Spool(cfg.SpoolDir(), r)
	if err != nil {
		return fmt.Errorf("report upload failed (%v) and could not be saved: %w", sendErr, err)
	}
	fmt.Fprintf(stderr, "pleno-dlp: report upload failed (%v); saved to %s; retry with: pleno-dlp telemetry send %s\n", sendErr, path, path)
	return fmt.Errorf("report not sent: %w", sendErr)
}

// checkFeedbackDetector requires a registered detector Type name exactly
// when the report is a false positive.
func checkFeedbackDetector(kind report.Kind, name string) error {
	if kind != report.KindFalsePositive {
		if name != "" {
			return errors.New("--detector is only valid with --kind false-positive")
		}
		return nil
	}
	if name == "" {
		return errors.New("--kind false-positive requires --detector <Type>; list types with: pleno-dlp detectors list")
	}
	for _, d := range detectors.All() {
		if d.Type().String() == name {
			return nil
		}
	}
	return fmt.Errorf("--detector %q is not a registered detector type; list types with: pleno-dlp detectors list", name)
}

// feedbackMessage reads the message from exactly one of the positional
// arguments, --file, or --stdin.
func feedbackMessage(c *cobra.Command, args []string) (string, error) {
	sources := 0
	for _, set := range []bool{len(args) > 0, feedbackOpts.file != "", feedbackOpts.stdin} {
		if set {
			sources++
		}
	}
	if sources != 1 {
		return "", errors.New("give the message exactly one way: as arguments, with --file <path>, or with --stdin")
	}
	switch {
	case feedbackOpts.stdin:
		if !feedbackOpts.yes && !feedbackOpts.dryRun {
			return "", errors.New("--stdin consumes the terminal the confirmation prompt needs; review with --dry-run, then re-run with --yes")
		}
		return readBounded(c.InOrStdin(), "stdin")
	case feedbackOpts.file != "":
		f, err := os.Open(feedbackOpts.file)
		if err != nil {
			return "", err
		}
		defer f.Close()
		return readBounded(f, feedbackOpts.file)
	}
	return strings.Join(args, " "), nil
}

func readBounded(r io.Reader, name string) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxFeedbackInput+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxFeedbackInput {
		return "", fmt.Errorf("%s: message exceeds %d bytes", name, maxFeedbackInput)
	}
	return strings.TrimSpace(string(b)), nil
}

// confirmFeedback asks on the terminal. Without a terminal it refuses,
// because a report must never leave the machine unreviewed by accident.
func confirmFeedback(c *cobra.Command) (bool, error) {
	if !feedbackInteractive(c.InOrStdin()) {
		return false, errors.New("refusing to send without confirmation: stdin is not a terminal; review with --dry-run, then re-run with --yes")
	}
	fmt.Fprint(c.ErrOrStderr(), "Send this anonymized report? [y/N] ")
	line, err := bufio.NewReader(c.InOrStdin()).ReadString('\n')
	if err != nil && line == "" {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

func feedbackRedactor() *report.Redactor {
	home, _ := os.UserHomeDir()
	return &report.Redactor{Prefixes: report.EnvPrefixes(telemetryGetenv, home), Detectors: detectors.All()}
}

// changedFlagNames lists the names, never the values, of flags set on c.
func changedFlagNames(c *cobra.Command) []string {
	names := []string{}
	c.Flags().Visit(func(f *pflag.Flag) { names = append(names, f.Name) })
	sort.Strings(names)
	return names
}

// printSent announces a successful upload. The intake repository is
// private, so the issue URL is only useful to maintainers; say so.
func printSent(c *cobra.Command, kind report.Kind, endpoint string, rc report.Receipt) {
	if rc.Issue != "" {
		fmt.Fprintf(c.OutOrStdout(), "%s report recorded as %s (private intake)\n", kind, rc.Issue)
		return
	}
	fmt.Fprintf(c.OutOrStdout(), "%s report sent to %s\n", kind, endpoint)
}
