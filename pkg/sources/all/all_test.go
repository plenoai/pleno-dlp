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

// TestAllRegisteredSourcesSupportIncremental asserts that every core source
// self-registered against sources.Register implements both incremental
// extensions. Derived from sources.Registered() (not a hand list) — #284
// closed the last gap (docker-image), so every registered source is now
// incremental-capable and a hand list would silently miss future additions.
func TestAllRegisteredSourcesSupportIncremental(t *testing.T) {
	for _, typ := range sources.Registered() {
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
