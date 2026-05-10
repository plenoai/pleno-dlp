// Stubs for connectors whose single-file Lambda-handler implementations
// have not landed yet. They register a Connector value so the CLI can
// surface them in `pleno-dlp list`, but Scan / Verify return a clear
// "not yet migrated" error instead of silently doing nothing.
//
// Each stub disappears the moment its full implementation lands as
// pkg/connectors/<name>.go. Tracked under issues #74-#80.

package connectors

import (
	"context"
	"fmt"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func init() {
	for _, s := range []struct {
		name string
		t    sources.SourceType
	}{
		{"bitbucket", sources.SourceBitbucket},
		{"notion", sources.SourceNotion},
		{"confluence", sources.SourceConfluence},
		{"jira", sources.SourceJira},
		{"slack", sources.SourceSlack},
	} {
		s := s
		Register(s.name, Connector{
			SourceType: s.t,
			Scan:       stubScan(s.name),
			Verify:     stubVerify(s.name),
		})
	}
}

func stubScan(name string) Scan {
	return func(_ context.Context, _ Config, _ Emit) error {
		return fmt.Errorf("%s: connector not yet migrated to Lambda-handler shape", name)
	}
}

func stubVerify(name string) Verify {
	return func(_ context.Context, _ Config, _ string) (bool, error) {
		return false, fmt.Errorf("%s: connector not yet migrated to Lambda-handler shape", name)
	}
}
