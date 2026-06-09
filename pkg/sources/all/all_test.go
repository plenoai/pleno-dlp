package all

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// TestAllRegistersRealSources asserts that blank-importing the aggregator
// package wires exactly the source types that self-register against
// sources.Register via init(): filesystem, git, s3, stdin, sqldump.
//
// SaaS types deliberately route through pkg/connectors and do NOT register
// against sources.Register, so sources.New must return nil for them. Asserting
// they resolve here would false-fail.
func TestAllRegistersRealSources(t *testing.T) {
	registered := []sources.SourceType{
		sources.SourceFilesystem,
		sources.SourceGit,
		sources.SourceS3,
		sources.SourceStdin,
		sources.SourceSQLDump,
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

func TestAllRegisteredSourcesSupportIncremental(t *testing.T) {
	registered := []sources.SourceType{
		sources.SourceFilesystem,
		sources.SourceGit,
		sources.SourceS3,
		sources.SourceStdin,
		sources.SourceSQLDump,
	}
	for _, typ := range registered {
		s := sources.New(typ)
		if s == nil {
			t.Errorf("sources.New(%s) = nil, want registered source", typ)
			continue
		}
		if _, ok := s.(sources.ResourceFingerprinter); !ok {
			t.Errorf("%s source does not implement ResourceFingerprinter", typ)
		}
		if _, ok := s.(sources.IncrementalStateSource); !ok {
			t.Errorf("%s source does not implement IncrementalStateSource", typ)
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
		sources.SourceGCS,
		sources.SourceSlack,
		sources.SourceJira,
		sources.SourceConfluence,
		sources.SourceAzureBlob,
		sources.SourceBitbucket,
		sources.SourceNotion,
		sources.SourceForgejo,
		sources.SourceGitea,
		sources.SourceGogs,
		sources.SourceGitbucket,
		sources.SourceCodeberg,
		sources.SourceOneDev,
		sources.SourceCodebase,
		sources.SourcePagure,
	}
	for _, typ := range saas {
		if s := sources.New(typ); s != nil {
			t.Errorf("sources.New(%s) = non-nil, want nil (SaaS routes through pkg/connectors)", typ)
		}
	}
}
