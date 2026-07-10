package connectors

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	"github.com/plenoai/pleno-dlp/pkg/engine"
)

type githubLargeOrgBenchmarkSink struct{ findings atomic.Int64 }

func (s *githubLargeOrgBenchmarkSink) Emit(engine.Finding) { s.findings.Add(1) }
func (*githubLargeOrgBenchmarkSink) Close() error          { return nil }

// TestGitHubLargeOrgBenchmark is an opt-in, deterministic selected-defaults
// benchmark. Run through bench/github-large-org.sh so peak RSS is measured by
// the operating system rather than inferred from Go heap counters.
func TestGitHubLargeOrgBenchmark(t *testing.T) {
	if os.Getenv("PLENO_RUN_LARGE_ORG_BENCH") != "1" {
		t.Skip("set PLENO_RUN_LARGE_ORG_BENCH=1")
	}
	const repoCount = 128
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "acme"), 0o700); err != nil {
		t.Fatal(err)
	}
	repos := make([]githubRepoRef, 0, repoCount)
	for i := 0; i < repoCount; i++ {
		fixture, _ := buildFixtureRepo(t)
		name := fmt.Sprintf("repo-%02d", i)
		if err := os.Symlink(fixture, filepath.Join(root, "acme", name)); err != nil {
			t.Fatal(err)
		}
		r := githubRepoRef{Name: name, Visibility: "private"}
		r.Owner.Login = "acme"
		repos = append(repos, r)
	}
	var apiCalls atomic.Int64
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiCalls.Add(1)
		if r.URL.Query().Get("page") == "2" {
			writeJSON(t, w, repos[100:])
			return
		}
		w.Header().Set("Link", fmt.Sprintf("<%s/orgs/acme/repos?per_page=100&type=all&page=2>; rel=\"next\"", srv.URL))
		writeJSON(t, w, repos[:100])
	}))
	defer srv.Close()
	var cloneBytes atomic.Int64
	githubCloneBytesObserver = func(_ string, n int64) { cloneBytes.Add(n) }
	defer func() { githubCloneBytesObserver = nil }()
	start := time.Now()
	src, err := AsSource("github", Config{"token": "benchmark", "org": "acme", "api_base": srv.URL, "clone_url_template": filepath.Join(root, "{owner}", "{repo}"), "repo_concurrency": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := src.Init(context.Background(), "github-benchmark", 0, 1, false, nil, 8); err != nil {
		t.Fatal(err)
	}
	sink := &githubLargeOrgBenchmarkSink{}
	eng := engine.New(engine.Options{Concurrency: 8, NoVerify: true}, sink)
	_, err = eng.RunWithStats(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	peakRSS := usage.Maxrss
	if runtime.GOOS == "linux" {
		peakRSS *= 1024
	}
	fmt.Printf("BENCHMARK github-large-org repos=%d wall_ms=%d peak_rss_bytes=%d clone_bytes=%d api_calls=%d findings=%d\n", repoCount, time.Since(start).Milliseconds(), peakRSS, cloneBytes.Load(), apiCalls.Load(), sink.findings.Load())
}
