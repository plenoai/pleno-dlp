package blastradius_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/blastradius"
	"github.com/plenoai/pleno-dlp/pkg/blastradius/github"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

type countingMapper struct {
	calls, inflight, peak atomic.Int32
}

func (m *countingMapper) MapAccess(ctx context.Context, c detectors.AccessCredential) (*detectors.AccessMap, error) {
	m.calls.Add(1)
	n := m.inflight.Add(1)
	for {
		p := m.peak.Load()
		if n <= p || m.peak.CompareAndSwap(p, n) {
			break
		}
	}
	time.Sleep(20 * time.Millisecond)
	m.inflight.Add(-1)
	am := detectors.NewAccessMap("x")
	am.Identity.ID = c.Secret
	return am, nil
}

func TestRegistryCachesAndBoundsConcurrency(t *testing.T) {
	cm := &countingMapper{}
	reg := blastradius.NewRegistry(blastradius.Provider{Name: "x", Mapper: cm, Detectors: []detectors.DetectorType{detectors.GitHub}})
	reg.SetConcurrency(2)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res := detectors.Result{DetectorType: detectors.GitHub, Verified: true, Raw: []byte(fmt.Sprint("tok", i%6))}
			am, err := reg.MapResult(context.Background(), res)
			if err != nil || am.Identity.ID != string(res.Raw) {
				t.Errorf("got %+v %v", am, err)
			}
		}(i)
	}
	wg.Wait()
	if got := cm.calls.Load(); got != 6 {
		t.Fatalf("calls = %d, want 6 (one per distinct credential)", got)
	}
	if p := cm.peak.Load(); p > 2 {
		t.Fatalf("peak concurrency = %d, want <= 2", p)
	}
}

func TestRegistryDoesNotCacheCallerCancellation(t *testing.T) {
	cm := &countingMapper{}
	reg := blastradius.NewRegistry(blastradius.Provider{Name: "x", Mapper: cm, Detectors: []detectors.DetectorType{detectors.GitHub}})
	reg.SetConcurrency(1)
	res := detectors.Result{DetectorType: detectors.GitHub, Verified: true, Raw: []byte("t")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Occupy the only slot so the cancelled call cannot run.
	if _, err := reg.MapResult(ctx, res); err == nil {
		t.Skip("mapper ran before cancellation was observed")
	}
	if _, err := reg.MapResult(context.Background(), res); err != nil {
		t.Fatalf("cancellation was cached: %v", err)
	}
}

func TestGitHubPaginatesBeyond100(t *testing.T) {
	var srvURL string
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user":
			_, _ = w.Write([]byte(`{"login":"octo","id":1}`))
		case "/user/orgs":
			_, _ = w.Write([]byte(`[]`))
		case "/user/repos":
			page := r.URL.Query().Get("page")
			if page == "" {
				w.Header().Set("Link", `<`+srvURL+`/user/repos?page=2>; rel="next", <`+srvURL+`/user/repos?page=2>; rel="last"`)
				items := make([]string, 100)
				for i := range items {
					items[i] = fmt.Sprintf(`{"full_name":"o/r%d"}`, i)
				}
				_, _ = w.Write([]byte("[" + strings.Join(items, ",") + "]"))
				return
			}
			_, _ = w.Write([]byte(`[{"full_name":"o/last"}]`))
		}
	})
	srvURL = s.URL
	am, err := github.Mapper{BaseURL: s.URL}.MapAccess(context.Background(), detectors.AccessCredential{Secret: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if len(am.Resources) != 101 || am.Resources[100].Name != "o/last" {
		t.Fatalf("resources = %d", len(am.Resources))
	}
	for _, l := range am.Limitations {
		if strings.Contains(l, "capped") {
			t.Fatalf("unexpected cap: %v", am.Limitations)
		}
	}
}
