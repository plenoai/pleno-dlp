package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
	"github.com/plenoai/pleno-dlp/pkg/telemetry/feedback"
)

var feedbackYes bool

var feedbackCmd = &cobra.Command{
	Use:   "feedback [message]",
	Short: "Send anonymized feedback to the pleno-dlp team",
	Long: `Feedback is sent to the same relay as crash reports but ignores the crash
opt-in: running this command is itself the consent. The message is redacted
(paths, emails, IPs, URLs, and tokens) and locally rate-limited. With no
message argument the message is read from stdin; use --yes to skip the
confirmation prompt in scripts.`,
	Args: cobra.ArbitraryArgs,
	RunE: runFeedback,
}

func init() {
	feedbackCmd.Flags().BoolVarP(&feedbackYes, "yes", "y", false, "send without the interactive confirmation prompt")
	Root.AddCommand(feedbackCmd)
}

func runFeedback(c *cobra.Command, args []string) error {
	cfg, err := crash.Load(telemetryGetenv)
	if err != nil {
		return err
	}
	msg, err := feedbackMessage(c, args)
	if err != nil {
		return err
	}
	if !feedbackYes {
		if !isInteractiveStdin(c.InOrStdin()) {
			return errors.New("feedback: refusing to send from a non-interactive context without --yes")
		}
		if !confirmFeedback(c) {
			fmt.Fprintln(c.OutOrStdout(), "feedback not sent")
			return nil
		}
	}

	th := &crash.Throttle{Dir: cfg.Dir}
	switch ok, terr := th.AllowFeedback(); {
	case terr != nil:
		fmt.Fprintf(c.ErrOrStderr(), "feedback: local throttle unavailable (%v); sending anyway\n", terr)
	case !ok:
		return fmt.Errorf("feedback: local rate limit reached (%d per hour); try again later", crash.FeedbackSendLimit)
	}

	r := feedback.Build(msg, toolVersion, toolCommit, time.Now())
	if err := feedback.Send(c.Context(), nil, cfg.Endpoint, toolVersion, r); err != nil {
		return err
	}
	fmt.Fprintf(c.OutOrStdout(), "feedback sent to %s\n", cfg.Endpoint)
	return nil
}

// feedbackMessage returns the message from the positional arguments, or reads
// it from stdin when none were given.
func feedbackMessage(c *cobra.Command, args []string) (string, error) {
	if len(args) > 0 {
		msg := strings.TrimSpace(strings.Join(args, " "))
		if msg == "" {
			return "", errors.New("feedback: empty message")
		}
		if len(msg) > feedback.MaxMessageBytes {
			return "", fmt.Errorf("feedback: message exceeds %d bytes", feedback.MaxMessageBytes)
		}
		return msg, nil
	}
	b, err := io.ReadAll(io.LimitReader(c.InOrStdin(), feedback.MaxMessageBytes+1))
	if err != nil {
		return "", fmt.Errorf("feedback: read message: %w", err)
	}
	if len(b) > feedback.MaxMessageBytes {
		return "", fmt.Errorf("feedback: message exceeds %d bytes", feedback.MaxMessageBytes)
	}
	msg := strings.TrimSpace(string(b))
	if msg == "" {
		return "", errors.New("feedback: empty message")
	}
	return msg, nil
}

// confirmFeedback asks on stderr and reads the answer from stdin.
func confirmFeedback(c *cobra.Command) bool {
	fmt.Fprint(c.ErrOrStderr(), "Send this feedback to pleno.ai? [y/N] ")
	line, _ := bufio.NewReader(c.InOrStdin()).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}
