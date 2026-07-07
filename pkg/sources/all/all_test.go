package all

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// TestAllRegistersRealSources asserts that blank-importing the aggregator
// package wires up every core source that self-registers against
// sources.Register via init(). The set comes from sources.Registered()
// rather than a hand-written list, so adding a new core source package
// (and importing it below) is automatically covered — a hand list here
// previously drifted silently and missed docker-image.
//
// SaaS types deliberately route through pkg/connectors and do NOT register
// against sources.Register, so sources.New must return nil for them. Asserting
// they resolve here would false-fail.
func TestAllRegistersRealSources(t *testing.T) {
	registered := sources.Registered()
	if len(registered) == 0 {
		t.Fatal("sources.Registered() returned nothing; is this package's import list empty?")
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

// incrementalCapableSources lists the core sources that implement
// ResourceFingerprinter and IncrementalStateSource. This stays a hand list
// (not sources.Registered()) because docker-image deliberately does not
// implement incremental state yet — looping over every registered type
// would false-fail on it. Extending docker-image's incremental support is
// tracked separately from #259's registry work.
var incrementalCapableSources = []sources.SourceType{
	sources.SourceFilesystem,
	sources.SourceGCS,
	sources.SourceGit,
	sources.SourceS3,
	sources.SourceStdin,
	sources.SourceSQLDump,
}

func TestAllRegisteredSourcesSupportIncremental(t *testing.T) {
	for _, typ := range incrementalCapableSources {
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
