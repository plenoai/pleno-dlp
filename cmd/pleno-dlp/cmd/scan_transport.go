package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/verify"
)

func init() {
	pf := scanCmd.PersistentFlags()
	pf.BoolVar(&scanOpts.noExtractArchives, "no-extract-archives", false,
		"scan archive files (zip, tar, gzip, bzip2, xz, zstd, jar, ...) as opaque bytes instead of expanding their entries")
	pf.BoolVar(&scanOpts.noDedup, "no-dedup", false,
		"report every finding: disable same-location dedup, generic-vs-provider collision suppression, and git cross-commit collapsing (implies scan git --all-occurrences)")
	pf.BoolVar(&scanOpts.ruleStats, "rule-stats", false,
		"print per-detector passes, candidate results, and wall time (slowest first) to stderr after the scan")
	pf.StringVar(&scanOpts.userAgentSuffix, "user-agent-suffix", "",
		"append this string to the User-Agent of every HTTP request (verification and SaaS APIs), e.g. 'acme-secops (+ops@example.com)'")
	pf.StringVarP(&scanOpts.outputPath, "output", "o", "",
		"write findings to this file (mode 0600, truncated) instead of stdout")
	scanFilesystemCmd.Flags().BoolVar(&fsOpts.scanNestedRepos, "scan-nested-repos", false,
		"also walk the full Git history of every repository found under the given paths")
}

// applyScanTransportAndOutput applies the scan flags that act on the
// process rather than the engine: the User-Agent suffix (installed before
// any verify transport so it sits at the base of http.DefaultTransport)
// and --output redirection.
func applyScanTransportAndOutput(cmd *cobra.Command) error {
	if err := verify.SetUserAgentSuffix(scanOpts.userAgentSuffix); err != nil {
		return err
	}
	for _, t := range scanOpts.inlineAllowTokens {
		if strings.TrimSpace(t) == "" {
			return fmt.Errorf("--inline-allow-token: empty token would allow every line")
		}
	}
	if scanOpts.outputPath == "" {
		return nil
	}
	f, err := os.OpenFile(scanOpts.outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("--output: %w", err)
	}
	cmd.SetOut(f)
	cobra.OnFinalize(func() {
		cmd.SetOut(nil)
		_ = f.Close()
	})
	return nil
}

// printDetectorStats renders --rule-stats on stderr so it never mixes with
// structured stdout.
func printDetectorStats(w io.Writer, stats []engine.DetectorStat) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DETECTOR\tPASSES\tRESULTS\tTIME")
	for _, s := range stats {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%s\n", s.Detector, s.Calls, s.Results, s.Duration.Round(time.Microsecond))
	}
	_ = tw.Flush()
}
