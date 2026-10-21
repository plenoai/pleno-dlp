package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/plenoai/pleno-dlp/pkg/telemetry/crash"
)

// telemetryGetenv is the environment lookup for telemetry commands; tests
// replace it to isolate the config directory.
var telemetryGetenv = os.Getenv

var telemetryCmd = &cobra.Command{
	Use:   "telemetry",
	Short: "Manage opt-in anonymized crash reports",
	Long: `Crash reports are disabled by default. When pleno-dlp crashes, a redacted
report is always written to the local spool; it is uploaded only after
'pleno-dlp telemetry enable' (or PLENO_DLP_CRASH_REPORTS=1). See docs/telemetry.md.`,
}

var telemetryEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Opt in to sending anonymized crash reports",
	Args:  cobra.NoArgs,
	RunE:  func(c *cobra.Command, _ []string) error { return setTelemetry(c, true) },
}

var telemetryDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Opt out of sending crash reports (local spool is kept)",
	Args:  cobra.NoArgs,
	RunE:  func(c *cobra.Command, _ []string) error { return setTelemetry(c, false) },
}

func setTelemetry(c *cobra.Command, enabled bool) error {
	path, err := crash.SetEnabled(telemetryGetenv, enabled)
	if err != nil {
		return err
	}
	state := map[bool]string{true: "enabled", false: "disabled"}[enabled]
	fmt.Fprintf(c.OutOrStdout(), "crash reports %s (%s)\n", state, path)
	if v := telemetryGetenv(crash.EnvReports); v != "" {
		fmt.Fprintf(c.ErrOrStderr(), "note: %s=%s overrides this setting\n", crash.EnvReports, v)
	}
	return nil
}

var telemetryStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether crash reports are sent, and where",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, _ []string) error {
		cfg, err := crash.Load(telemetryGetenv)
		if err != nil {
			return err
		}
		state := "disabled"
		if cfg.Enabled {
			state = "enabled"
		}
		w := c.OutOrStdout()
		fmt.Fprintf(w, "crash reports: %s\n", state)
		fmt.Fprintf(w, "source:        %s\n", cfg.Source)
		fmt.Fprintf(w, "endpoint:      %s\n", cfg.Endpoint)
		fmt.Fprintf(w, "spool dir:     %s\n", cfg.SpoolDir())
		return nil
	},
}

var telemetryShowLastCmd = &cobra.Command{
	Use:   "show-last",
	Short: "Print the most recent spooled crash report",
	Args:  cobra.NoArgs,
	RunE: func(c *cobra.Command, _ []string) error {
		cfg, err := crash.Load(telemetryGetenv)
		if cfg.Dir == "" {
			return err
		}
		path := filepath.Join(cfg.SpoolDir(), crash.LastFile)
		_, raw, err := crash.ReadReport(path)
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("no crash report spooled at %s", path)
		}
		if err != nil {
			return err
		}
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, raw, "", "  "); err != nil {
			return err
		}
		fmt.Fprintln(c.OutOrStdout(), strings.TrimRight(pretty.String(), "\n"))
		return nil
	},
}

var telemetrySendCmd = &cobra.Command{
	Use:   "send <file>",
	Short: "Send a reviewed spooled crash report",
	Long: `Send uploads the file exactly as it is on disk, so what you reviewed is
what is sent. Only files matching the crash report schema are accepted.
Sending is an explicit action and does not require 'telemetry enable'.`,
	Args: cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) error {
		cfg, err := crash.Load(telemetryGetenv)
		if err != nil {
			return err
		}
		r, _, err := crash.ReadReport(args[0])
		if err != nil {
			return err
		}
		if err := crash.Send(c.Context(), nil, cfg.Endpoint, toolVersion, r); err != nil {
			return err
		}
		fmt.Fprintf(c.OutOrStdout(), "sent crash report %s to %s\n", r.Fingerprint, cfg.Endpoint)
		return nil
	},
}

var crashTestGoroutine bool

// telemetryCrashTestCmd exists for end-to-end verification of both capture
// paths: a main-goroutine panic (recoverable in-process) and a spawned
// goroutine panic (only the supervisor can observe it).
var telemetryCrashTestCmd = &cobra.Command{
	Use:    "crash-test",
	Short:  "Deliberately panic to exercise crash reporting",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		const msg = "pleno-dlp telemetry crash-test"
		if !crashTestGoroutine {
			panic(msg)
		}
		block := make(chan struct{})
		go func() { panic(msg + " (goroutine)") }()
		<-block
		return nil
	},
}

func init() {
	telemetryCrashTestCmd.Flags().BoolVar(&crashTestGoroutine, "goroutine", false, "panic in a spawned goroutine instead of the main goroutine")
	telemetryCmd.AddCommand(telemetryEnableCmd, telemetryDisableCmd, telemetryStatusCmd,
		telemetryShowLastCmd, telemetrySendCmd, telemetryCrashTestCmd)
	Root.AddCommand(telemetryCmd)
}

// DescribeInvocation maps args (argv without the program name) to the
// subcommand path and the names of recognised flags. Values, positional
// arguments, and unrecognised tokens are never returned, so the result is
// safe to put in a crash report.
//
// Flag names are collected from the whole argument vector rather than only
// the tokens cobra's Find leaves after the command, so a root/persistent
// flag given before its subcommand (`pleno-dlp --crash-report out scan ...`)
// is recorded too (#516).
func DescribeInvocation(args []string) (string, []string) {
	c, _, err := Root.Find(args)
	if err != nil || c == nil {
		return "", []string{}
	}
	command := strings.TrimSpace(strings.TrimPrefix(c.CommandPath(), Root.Name()))
	seen := map[string]bool{}
	lookup := func(name string) *pflag.Flag {
		if f := c.Flags().Lookup(name); f != nil {
			return f
		}
		return c.InheritedFlags().Lookup(name)
	}
	short := func(s string) *pflag.Flag {
		if f := c.Flags().ShorthandLookup(s); f != nil {
			return f
		}
		return c.InheritedFlags().ShorthandLookup(s)
	}
	for _, a := range args {
		if a == "--" {
			break
		}
		var f *pflag.Flag
		switch {
		case strings.HasPrefix(a, "--"):
			name, _, _ := strings.Cut(a[2:], "=")
			f = lookup(name)
		case strings.HasPrefix(a, "-") && len(a) >= 2:
			f = short(a[1:2])
		}
		if f != nil {
			seen[f.Name] = true
		}
	}
	flags := make([]string, 0, len(seen))
	for n := range seen {
		flags = append(flags, n)
	}
	sort.Strings(flags)
	return command, flags
}
