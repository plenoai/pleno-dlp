package connectors

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestForgeConnectorRegistrations(t *testing.T) {
	cases := map[string]sources.SourceType{
		"forgejo":   sources.SourceForgejo,
		"gitea":     sources.SourceGitea,
		"gogs":      sources.SourceGogs,
		"gitbucket": sources.SourceGitbucket,
		"codeberg":  sources.SourceCodeberg,
		"onedev":    sources.SourceOneDev,
		"codebase":  sources.SourceCodebase,
		"pagure":    sources.SourcePagure,
	}
	for name, wantType := range cases {
		conn, ok := Get(name)
		if !ok {
			t.Fatalf("Get(%q) ok = false, want true", name)
		}
		if conn.Scan == nil {
			t.Fatalf("Get(%q).Scan = nil, want scan implementation", name)
		}
		if conn.SourceType != wantType {
			t.Fatalf("Get(%q).SourceType = %s, want %s", name, conn.SourceType, wantType)
		}
	}
}
