package all

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// TestAllRegistersRealSources asserts that blank-importing the aggregator
// package wires exactly the source types that self-register against
// sources.Register via init(): filesystem, git, stdin.
//
// SaaS types (GitHub, GitLab, S3, GCS, Slack, Jira, Confluence, AzureBlob,
// Bitbucket, Notion) deliberately route through pkg/connectors and do NOT
// register against sources.Register, so sources.New must return nil for them.
// Asserting they resolve here would false-fail.
func TestAllRegistersRealSources(t *testing.T) {
	registered := []sources.SourceType{
		sources.SourceFilesystem,
		sources.SourceGit,
		sources.SourceStdin,
	}
	for _, typ := range registered {
		s := sources.New(typ)
		if s == nil {
			t.Errorf("sources.New(%s) = nil, want registered source", typ)
			continue
		}
		if s.Type() != typ {
			t.Errorf("sources.New(%s).Type() = %s, want %s", typ, s.Type(), typ)
		}
	}
}

// TestAllDoesNotRegisterSaaS guards the source/connector boundary: SaaS types
// are served by pkg/connectors, not the sources registry, so sources.New must
// not resolve them even after the aggregator is imported.
func TestAllDoesNotRegisterSaaS(t *testing.T) {
	saas := []sources.SourceType{
		sources.SourceGitHub,
		sources.SourceGitLab,
		sources.SourceS3,
		sources.SourceGCS,
		sources.SourceSlack,
		sources.SourceJira,
		sources.SourceConfluence,
		sources.SourceAzureBlob,
		sources.SourceBitbucket,
		sources.SourceNotion,
	}
	for _, typ := range saas {
		if s := sources.New(typ); s != nil {
			t.Errorf("sources.New(%s) = non-nil, want nil (SaaS routes through pkg/connectors)", typ)
		}
	}
}
