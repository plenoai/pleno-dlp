// SaaS connector dispatch helpers. Each per-connector cmd file translates
// its flag set into a connectors.Config, then hands off to runScanSaaS or
// runVerifySaaS — keeping per-cmd logic tight and the dispatch shape
// uniform across providers.

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

// runScanSaaS wraps the named connector as a sources.Source and runs the
// shared scan pipeline. cfg is built by the caller from the cmd's flags;
// connectors validate the keys they need internally.
func runScanSaaS(cmd *cobra.Command, name string, cfg connectors.Config) error {
	src, err := connectors.AsSource(name, cfg)
	if err != nil {
		return err
	}
	return runScanCommon(cmd, src, nil, name)
}

// runVerifySaaS dispatches the configured token to the connector's Verify
// function and renders a single-line outcome to cmd's stdout. Missing
// connector / missing Verify / Verify error / not-verified all return
// non-nil; only "verified" returns nil.
func runVerifySaaS(cmd *cobra.Command, name, secret string, cfg connectors.Config) error {
	c, ok := connectors.Get(name)
	if !ok {
		return fmt.Errorf("%s connector is not registered", name)
	}
	if c.Verify == nil {
		return fmt.Errorf("%s connector does not implement verify", name)
	}
	verified, err := c.Verify(cmdContext(cmd), cfg, secret)
	if err != nil {
		return fmt.Errorf("%s: verify: %w", name, err)
	}
	if !verified {
		fmt.Fprintf(cmd.OutOrStdout(), "%s: token NOT verified (401 / 403)\n", name)
		return errVerifyFailed
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%s: token verified\n", name)
	return nil
}
