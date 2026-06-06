package sources

import (
	"context"
	"testing"
)

// TestSourceTypeString pins the String() rendering for every SourceType,
// including SourceUnknown and an out-of-range value. SourceType.String()
// drives output routing, so a silent change here would mis-label results.
func TestSourceTypeString(t *testing.T) {
	cases := []struct {
		typ  SourceType
		want string
	}{
		{SourceUnknown, "unknown"},
		{SourceFilesystem, "filesystem"},
		{SourceGit, "git"},
		{SourceGitHub, "github"},
		{SourceGitLab, "gitlab"},
		{SourceS3, "s3"},
		{SourceGCS, "gcs"},
		{SourceSlack, "slack"},
		{SourceJira, "jira"},
		{SourceConfluence, "confluence"},
		{SourceAzureBlob, "azure-blob"},
		{SourceBitbucket, "bitbucket"},
		{SourceNotion, "notion"},
		{SourceStdin, "stdin"},
		{SourceForgejo, "forgejo"},
		{SourceGitea, "gitea"},
		{SourceGogs, "gogs"},
		{SourceGitbucket, "gitbucket"},
		{SourceCodeberg, "codeberg"},
		{SourceOneDev, "onedev"},
		{SourceCodebase, "codebase"},
		{SourcePagure, "pagure"},
		{SourceType(9999), "unknown"},
	}
	for _, c := range cases {
		if got := c.typ.String(); got != c.want {
			t.Errorf("SourceType(%d).String() = %q, want %q", c.typ, got, c.want)
		}
	}
}

// stubSource is a minimal Source used to exercise Register/New without
// depending on any concrete source package (which would couple this
// internal test to the registry global state populated by init()).
type stubSource struct {
	typ SourceType
}

func (s *stubSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}
func (s *stubSource) Chunks(context.Context, chan<- *Chunk) error { return nil }
func (s *stubSource) Type() SourceType                            { return s.typ }

// registerIsolated registers under a lock-protected swap of the global map so
// the test does not leak entries into other tests or collide with init()
// registrations from imported source packages.
func withCleanRegistry(t *testing.T) {
	t.Helper()
	mu.Lock()
	saved := registry
	registry = map[SourceType]Factory{}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	})
}

// TestRegisterNewRoundTrip verifies a registered factory is returned by New
// and that an unregistered type yields nil.
func TestRegisterNewRoundTrip(t *testing.T) {
	withCleanRegistry(t)

	want := &stubSource{typ: SourceFilesystem}
	Register(SourceFilesystem, func() Source { return want })

	got := New(SourceFilesystem)
	if got == nil {
		t.Fatal("New(SourceFilesystem) = nil, want registered source")
	}
	if got.Type() != SourceFilesystem {
		t.Errorf("got.Type() = %v, want %v", got.Type(), SourceFilesystem)
	}

	if New(SourceGit) != nil {
		t.Error("New(SourceGit) = non-nil for unregistered type, want nil")
	}
}

// TestRegisterDuplicatePanics verifies the second Register of the same type
// panics, guarding against two sources claiming one SourceType.
func TestRegisterDuplicatePanics(t *testing.T) {
	withCleanRegistry(t)

	Register(SourceGit, func() Source { return &stubSource{typ: SourceGit} })

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("duplicate Register did not panic")
		}
	}()
	Register(SourceGit, func() Source { return &stubSource{typ: SourceGit} })
}
