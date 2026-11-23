// SaaS connector dispatch helpers. Each per-connector cmd file translates
// its flag set into a connectors.Config, then hands off to runScanSaaS or
// runVerifySaaS — keeping per-cmd logic tight and the dispatch shape
// uniform across providers.

package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
)

// runScanSaaS wraps the named connector as a sources.Source and runs the
// shared scan pipeline. cfg is built by the caller from the cmd's flags;
// connectors validate the keys they need internally.
func runScanSaaS(cmd *cobra.Command, name string, cfg connectors.Config) error {
	if scanOpts.listOnly {
		return runListOnly(cmd, name, cfg)
	}
	src, err := connectors.AsSource(name, cfg)
	if err != nil {
		return err
	}
	scope, err := saasScopeDescriptor(name, cfg)
	if err != nil {
		return err
	}
	return runScanCommon(cmd, src, scope, name)
}

// saasScopeKeys lists the connector config keys that identify *what* is
// scanned. Only these reach the incremental fingerprint, so credentials
// (token, api_key, sas_token, app_password, private keys, ...) can never be
// hashed into or persisted alongside --incremental-state. Allowlist, not
// denylist: a new secret key is excluded by default (#864).
var saasScopeKeys = map[string]bool{
	"account": true, "api_base": true, "base_url": true, "channel": true,
	"container_url": true, "group": true, "host": true, "jql": true,
	"org": true, "prefix": true, "project": true, "query": true,
	"query_ids": true, "repo": true, "space": true, "team_ids": true,
	"user": true, "username": true, "workspace": true, "email": true,
	"include_repo_globs": true, "exclude_repo_globs": true,
	"history": true, "include_snippets": true, "include_comments": true,
	"include_issues": true, "include_pull_requests": true, "include_wikis": true,
	"since_commit": true, "branch_root_commit": true,
}

// saasScopeDescriptor returns a credential-free canonical JSON descriptor of
// the scan scope so distinct scopes of one connector get distinct
// incremental-state entries. URL query strings and userinfo are stripped
// because SAS tokens and basic-auth credentials travel there.
func saasScopeDescriptor(name string, cfg connectors.Config) ([]byte, error) {
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		if saasScopeKeys[k] && cfg[k] != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	scope := make(map[string]string, len(keys))
	for _, k := range keys {
		scope[k] = stripURLSecrets(cfg[k])
	}
	return json.Marshal(map[string]any{"connector": name, "scope": scope})
}

func stripURLSecrets(v string) string {
	u, err := url.Parse(v)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return v
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
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
