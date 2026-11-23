package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// validate runs one detector's live verification against operator-supplied
// text, without a scan source: the kingfisher `validate --rule --secret`
// equivalent. The secret should come from stdin (`--secret -`) so it never
// lands in shell history or the process table.

var validateOpts struct {
	detector        string
	secret          string
	format          string
	timeout         time.Duration
	skipAWSAccounts []string
	skipAWSFile     string
}

var validateCmd = &cobra.Command{
	Use:   "validate --detector <type> --secret <value|->",
	Short: "Verify one secret against its provider with a named detector",
	Long: "Runs the named detector over the supplied text with live verification enabled and\n" +
		"reports each match's verdict. Pass --secret - to read the text from stdin; paired\n" +
		"credentials (for example an AWS key ID and secret key) can be supplied together on\n" +
		"separate lines. Exit 0 when at least one match verifies, 1 otherwise.",
	Args: cobra.NoArgs,
	RunE: runValidate,
}

func init() {
	validateCmd.Flags().StringVar(&validateOpts.detector, "detector", "", "detector type name (see 'pleno-dlp detectors list')")
	validateCmd.Flags().StringVar(&validateOpts.secret, "secret", "", "secret text, or - to read it from stdin (recommended)")
	validateCmd.Flags().StringVar(&validateOpts.format, "format", "table", "output format: table|json")
	validateCmd.Flags().DurationVar(&validateOpts.timeout, "timeout", 30*time.Second, "overall verification timeout")
	validateCmd.Flags().StringSliceVar(&validateOpts.skipAWSAccounts, "skip-aws-account", nil, "AWS account ID(s) never verified (canary tokens)")
	validateCmd.Flags().StringVar(&validateOpts.skipAWSFile, "skip-aws-account-file", "", "file of AWS account IDs never verified")
	Root.AddCommand(validateCmd)
}

type validateRecord struct {
	Detector string `json:"detector"`
	Redacted string `json:"redacted"`
	Verdict  string `json:"verdict"`
	Verified bool   `json:"verified"`
	Error    string `json:"error,omitempty"`
	Skipped  string `json:"skipped,omitempty"`
}

func runValidate(cmd *cobra.Command, _ []string) error {
	if validateOpts.detector == "" || validateOpts.secret == "" {
		return errors.New("--detector and --secret are required")
	}
	if validateOpts.format != "table" && validateOpts.format != "json" {
		return fmt.Errorf("--format: unknown value %q (valid: table, json)", validateOpts.format)
	}
	det, err := detectorByName(validateOpts.detector)
	if err != nil {
		return err
	}
	if err := applySkipAWSAccounts(validateOpts.skipAWSAccounts, validateOpts.skipAWSFile); err != nil {
		return err
	}
	text, err := readValidateSecret(cmd, validateOpts.secret)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmdContext(cmd), validateOpts.timeout)
	defer cancel()
	results, err := det.FromData(ctx, true, []byte(text))
	if err != nil {
		return fmt.Errorf("%s: %w", det.Type(), err)
	}
	if len(results) == 0 {
		return fmt.Errorf("%s: the supplied text does not match this detector's pattern", det.Type())
	}
	recs := make([]validateRecord, 0, len(results))
	anyVerified := false
	for _, r := range results {
		rec := validateRecord{
			Detector: det.Type().String(),
			Redacted: r.SafeRedacted(),
			Verdict:  r.Verdict().String(),
			Verified: r.Verified,
			Skipped:  r.ExtraData["verification_skipped"],
		}
		if r.VerificationErr != nil {
			rec.Error = r.VerificationErr.Error()
		}
		anyVerified = anyVerified || r.Verified
		recs = append(recs, rec)
	}
	out := cmd.OutOrStdout()
	if validateOpts.format == "json" {
		enc := json.NewEncoder(out)
		for _, rec := range recs {
			if err := enc.Encode(rec); err != nil {
				return err
			}
		}
	} else {
		for _, rec := range recs {
			line := fmt.Sprintf("%s  %s  %s", rec.Detector, rec.Redacted, rec.Verdict)
			if rec.Skipped != "" {
				line += "  (skipped: " + rec.Skipped + ")"
			}
			if rec.Error != "" {
				line += "  error: " + rec.Error
			}
			fmt.Fprintln(out, line)
		}
	}
	if !anyVerified {
		return errVerifyFailed
	}
	return nil
}

// validateDetectors is the lookup set; tests substitute fakes.
var validateDetectors = detectors.All

// detectorByName resolves a registered detector by case-insensitive type
// name.
func detectorByName(name string) (detectors.Detector, error) {
	want := strings.ToLower(strings.TrimSpace(name))
	for _, d := range validateDetectors() {
		if strings.ToLower(d.Type().String()) == want {
			return d, nil
		}
	}
	return nil, fmt.Errorf("--detector %q: unknown detector (see 'pleno-dlp detectors list')", name)
}

func readValidateSecret(cmd *cobra.Command, raw string) (string, error) {
	if raw != "-" {
		return raw, nil
	}
	const maxBytes = 64 << 10
	buf, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), maxBytes+1))
	if err != nil {
		return "", fmt.Errorf("read secret from stdin: %w", err)
	}
	if len(buf) > maxBytes {
		return "", fmt.Errorf("read secret from stdin: input exceeds %d bytes", maxBytes)
	}
	return string(buf), nil
}
