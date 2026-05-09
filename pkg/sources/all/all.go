// Package all blank-imports every concrete source so their init() registers
// against pkg/sources.registry. Per ADR-0002, the CLI binary blank-imports
// this package; new sources add a single import line below.
package all

import (
	// SaaS connector ports register against both the connector registry
	// (for `pleno-dlp scan|verify <connector>` dispatch) and the source
	// registry (so the engine drives them via the same Source contract
	// it uses for filesystem/git/stdin). Keeping the blank-import here
	// — rather than in cmd/ — means a fresh `go test ./...` against
	// any package that touches sources picks up every registered SaaS
	// connector, mirroring what happens for the local sources below.
	_ "github.com/plenoai/pleno-dlp/pkg/connectors/github"
	_ "github.com/plenoai/pleno-dlp/pkg/connectors/gitlab"
	_ "github.com/plenoai/pleno-dlp/pkg/connectors/bitbucket"
	_ "github.com/plenoai/pleno-dlp/pkg/connectors/notion"
	_ "github.com/plenoai/pleno-dlp/pkg/connectors/confluence"
	_ "github.com/plenoai/pleno-dlp/pkg/connectors/jira"
	_ "github.com/plenoai/pleno-dlp/pkg/connectors/slack"

	_ "github.com/plenoai/pleno-dlp/pkg/sources/filesystem"
	_ "github.com/plenoai/pleno-dlp/pkg/sources/git"
	_ "github.com/plenoai/pleno-dlp/pkg/sources/stdin"
)
