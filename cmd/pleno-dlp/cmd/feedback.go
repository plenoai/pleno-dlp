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
	stdin bool
	yes   bool
}

var feedbackOpts feedbackFlags

var feedbackCmd = &cobra.Command{
	Use:   "feedback [message]",
	Short: "Send anonymized feedback to the pleno-dlp maintainers",
	Long: `Send a short message to the pleno-dlp maintainers. The message is redacted
with the same pipeline as crash reports before it leaves the machine, every
sent report is also saved to a local spool, and nothing is uploaded until you
confirm at the terminal (or pass --yes).

  pleno-dlp feedback "scan of a 2 GB monorepo OOMs"
  echo "docs typo in verify-coverage.md" | pleno-dlp feedback --stdin`,
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

	red := &crash.Redactor{Detectors: detectors.All()}
	if home, err := os.UserHomeDir(); err == nil {
		red.Prefixes = crash.EnvPrefixes(feedbackGetenv, home)
	}
	var flags []string
	c.Flags().Visit(func(f *pflag.Flag) { flags = append(flags, f.Name) })
	sort.Strings(flags)
	report := feedback.Build(message, crash.Meta{
		Version: toolVersion,
		Commit:  toolCommit,
		Command: "feedback",
		Flags:   flags,
	}, red, time.Now())

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

	cfg, err := crash.Load(feedbackGetenv)
	if err != nil {
		return err
	}
	throttle := &crash.Throttle{Dir: cfg.Dir}
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

// feedbackMessage resolves the message from --stdin or the positional args.
func feedbackMessage(c *cobra.Command, args []string) (string, error) {
	if feedbackOpts.stdin {
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
	fmt.Fprintf(c.ErrOrStderr(), "%s\n\nSend this feedback report to %s? [y/N] ", report.Message, endpoint)
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
	feedbackCmd.Flags().BoolVar(&feedbackOpts.yes, "yes", false, "skip the interactive confirmation prompt and send immediately")
	Root.AddCommand(feedbackCmd)
}
