package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/blastradius"
	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// scanBlastRadius backs `scan --blast-radius`. It lives here rather than in
// scanOpts to keep scan.go edits additive.
var scanBlastRadius bool

// blastRadiusRegistry is swapped by tests for httptest-backed mappers.
var blastRadiusRegistry = blastradius.Default

const blastRadiusTimeout = 60 * time.Second

var blastRadiusCmd = &cobra.Command{
	Use:     "blast-radius <provider> [credential_file]",
	Aliases: []string{"access-map"},
	Short:   "Map a credential to its identity, permissions, and reachable resources",
	Long: "Authenticate to the provider with the given credential and report the identity it\n" +
		"resolves to, its permissions, and the resources it can reach as JSON\n" +
		"(schema " + "pleno-dlp.access-map/v1" + ").\n\n" +
		"Providers: " + strings.Join(blastradius.Default().Names(), ", ") + ".\n" +
		"The credential is read from credential_file, or stdin when omitted or '-'.\n" +
		"  aws:    JSON {\"access_key_id\",\"secret_access_key\",\"session_token\"?} or id:secret\n" +
		"  gcp:    service-account JSON key file\n" +
		"  others: bare token, or JSON {\"token\",\"api_endpoint\"?,\"email\"?,\"username\"?}\n" +
		"          (gitea, jira, confluence require api_endpoint; jira/confluence take email,\n" +
		"          bitbucket app passwords take username)\n\n" +
		"This performs authenticated network requests. Only run it against accounts you\n" +
		"are authorized to inspect.",
	Args: cobra.RangeArgs(1, 2),
	RunE: runBlastRadius,
}

func init() {
	Root.AddCommand(blastRadiusCmd)
	scanCmd.PersistentFlags().BoolVar(&scanBlastRadius, "blast-radius", false,
		"for verified findings from supported detectors (see pleno-dlp blast-radius --help for providers), "+
			"make additional authenticated requests to map identity, permissions, and resources; "+
			"the JSON result is attached as extra_data."+blastradius.ExtraDataKey+" and a privileged map sets blast_radius=true. "+
			"Implies network access; ignored with --no-verify.")
}

func runBlastRadius(cmd *cobra.Command, args []string) error {
	reg := blastRadiusRegistry()
	p, ok := reg.Lookup(args[0])
	if !ok {
		return fmt.Errorf("unknown provider %q (supported: %s)", args[0], strings.Join(reg.Names(), ", "))
	}
	var data []byte
	var err error
	if len(args) == 1 || args[1] == "-" {
		data, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), 1<<20))
	} else {
		data, err = os.ReadFile(args[1])
	}
	if err != nil {
		return fmt.Errorf("read credential: %w", err)
	}
	cred, err := blastradius.ParseCredentialFile(p.Name, data)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), blastRadiusTimeout)
	defer cancel()
	am, err := p.Mapper.MapAccess(ctx, cred)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(am)
}

// blastRadiusMapSink attaches an AccessMap to verified findings whose
// detector has a registered mapper. It sits before --blast-radius-only so a
// privileged map promotes the finding into that filter, and outside the
// revoker so mapping happens before a credential is invalidated.
type blastRadiusMapSink struct {
	inner engine.Sink
	reg   *blastradius.Registry
}

func (b *blastRadiusMapSink) Emit(f engine.Finding) {
	if f.Result.Verified && b.reg.Supports(f.Result.DetectorType) {
		ctx, cancel := context.WithTimeout(context.Background(), blastRadiusTimeout)
		am, err := b.reg.MapResult(ctx, f.Result)
		cancel()
		extra := maps.Clone(f.Result.ExtraData)
		if extra == nil {
			extra = map[string]string{}
		}
		switch {
		case err != nil:
			extra["blast_radius_error"] = err.Error()
		case am != nil:
			if enc, mErr := json.Marshal(am); mErr == nil {
				extra[blastradius.ExtraDataKey] = string(enc)
			}
			extra["blast_radius_privileged"] = strconv.FormatBool(am.Privileged)
			if am.Privileged {
				extra["blast_radius"] = "true"
			}
		}
		f.Result.ExtraData = extra
	}
	b.inner.Emit(f)
}

func (b *blastRadiusMapSink) Close() error { return b.inner.Close() }
