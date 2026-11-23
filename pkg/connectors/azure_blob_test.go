package connectors

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const azureTestSig = "c2VjcmV0LXNpZ25hdHVyZQ%3D%3D"

type fakeAzureContainer struct {
	mu       sync.Mutex
	blobs    map[string]string // name -> body
	etags    map[string]string
	gets     map[string]int
	failBlob string
}

func (f *fakeAzureContainer) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sig") != "c2VjcmV0LXNpZ25hdHVyZQ==" || r.Header.Get("x-ms-version") == "" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprintf(w, `<?xml version="1.0"?><Error><Code>AuthenticationFailed</Code><Message>sig=%s</Message></Error>`, r.URL.Query().Get("sig"))
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/ctr" && r.URL.Query().Get("comp") == "list" {
			names := make([]string, 0, len(f.blobs))
			for n := range f.blobs {
				if strings.HasPrefix(n, r.URL.Query().Get("prefix")) {
					names = append(names, n)
				}
			}
			sort.Strings(names)
			// one blob per page to exercise marker pagination
			start := 0
			if m := r.URL.Query().Get("marker"); m != "" {
				for i, n := range names {
					if n == m {
						start = i
					}
				}
			}
			var b strings.Builder
			b.WriteString(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs>`)
			if start < len(names) {
				n := names[start]
				fmt.Fprintf(&b, `<Blob><Name>%s</Name><Properties><Etag>%s</Etag><Content-Length>%d</Content-Length></Properties></Blob>`, n, f.etags[n], len(f.blobs[n]))
			}
			b.WriteString(`</Blobs><NextMarker>`)
			if start+1 < len(names) {
				b.WriteString(names[start+1])
			}
			b.WriteString(`</NextMarker></EnumerationResults>`)
			_, _ = w.Write([]byte(b.String()))
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/ctr/")
		body, ok := f.blobs[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		f.gets[name]++
		if name == f.failBlob {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `<Error><Code>InternalError</Code><Message>%s</Message></Error>`, r.URL.RawQuery)
			return
		}
		_, _ = w.Write([]byte(body))
	})
}

func collectAzure(t *testing.T, cfg Config) ([]sources.Metadata, []string, error) {
	t.Helper()
	var metas []sources.Metadata
	var bodies []string
	err := scanAzureBlob(context.Background(), cfg, func(data []byte, meta sources.Metadata) error {
		metas = append(metas, meta)
		bodies = append(bodies, string(data))
		return nil
	})
	return metas, bodies, err
}

func TestAzureBlobScanPaginatesAndCheckpointsOnETag(t *testing.T) {
	fake := &fakeAzureContainer{
		blobs: map[string]string{"a.env": "A=1", "dir/b.txt": "B=2", "c d.txt": "C=3"},
		etags: map[string]string{"a.env": "0x1", "dir/b.txt": "0x2", "c d.txt": "0x3"},
		gets:  map[string]int{},
	}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	cfg := Config{"container_url": srv.URL + "/ctr", "sas_token": "?sv=2021-08-06&sp=rl&sig=" + azureTestSig}
	metas, bodies, err := collectAzure(t, cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(metas) != 3 {
		t.Fatalf("got %d chunks, want 3: %v", len(metas), bodies)
	}
	for _, m := range metas {
		if m.AzureBlob == nil || m.AzureBlob.Container != "ctr" || m.AzureBlob.Endpoint != srv.URL {
			t.Fatalf("bad metadata: %+v", m.AzureBlob)
		}
		if strings.Contains(m.AzureBlob.Locator(), "sig") {
			t.Fatalf("locator leaks SAS: %s", m.AzureBlob.Locator())
		}
	}
	state := cfg[configKeyIncrementalNextState]
	if state == "" || strings.Contains(state, "sig") {
		t.Fatalf("bad next state %q", state)
	}

	// second run: only the changed blob is downloaded again.
	fake.etags["dir/b.txt"] = "0x22"
	cfg2 := Config{"container_url": srv.URL + "/ctr?sv=2021-08-06&sp=rl&sig=" + azureTestSig, configKeyIncrementalPreviousState: state}
	metas, _, err = collectAzure(t, cfg2)
	if err != nil {
		t.Fatalf("incremental scan: %v", err)
	}
	if len(metas) != 1 || metas[0].AzureBlob.Blob != "dir/b.txt" {
		t.Fatalf("incremental scan emitted %+v, want only dir/b.txt", metas)
	}
	if fake.gets["a.env"] != 1 || fake.gets["dir/b.txt"] != 2 {
		t.Fatalf("unexpected GET counts %v", fake.gets)
	}
}

func TestAzureBlobErrorsNeverContainSAS(t *testing.T) {
	fake := &fakeAzureContainer{
		blobs: map[string]string{"ok.txt": "x", "bad.txt": "y"},
		etags: map[string]string{"ok.txt": "1", "bad.txt": "2"},
		gets:  map[string]int{}, failBlob: "bad.txt",
	}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	// download failure: degraded, not fatal, and the failed blob is retried next run.
	cfg := Config{"container_url": srv.URL + "/ctr", "sas_token": "sp=rl&sig=" + azureTestSig}
	metas, _, err := collectAzure(t, cfg)
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || len(metas) != 1 {
		t.Fatalf("want degraded error with 1 chunk, got %v / %d", err, len(metas))
	}
	if strings.Contains(cfg[configKeyIncrementalNextState], "bad.txt") {
		t.Fatalf("failed blob must not be checkpointed: %s", cfg[configKeyIncrementalNextState])
	}
	assertNoSAS(t, err)

	// auth failure on listing.
	_, _, err = collectAzure(t, Config{"container_url": srv.URL + "/ctr", "sas_token": "sp=rl&sig=wrongsig"})
	if err == nil || !strings.Contains(err.Error(), "AuthenticationFailed") || strings.Contains(err.Error(), "wrongsig") {
		t.Fatalf("auth error should carry the code but not the SAS: %v", err)
	}

	// transport failure: *url.Error would embed the URL.
	srv.Close()
	_, _, err = collectAzure(t, Config{"container_url": srv.URL + "/ctr", "sas_token": "sp=rl&sig=" + azureTestSig})
	if err == nil {
		t.Fatal("want transport error")
	}
	assertNoSAS(t, err)
}

func assertNoSAS(t *testing.T, err error) {
	t.Helper()
	for _, s := range []string{azureTestSig, "c2VjcmV0LXNpZ25hdHVyZQ", "sig="} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("error leaks SAS (%q): %v", s, err)
		}
	}
}

func TestAzureBlobConfigValidation(t *testing.T) {
	for name, cfg := range map[string]Config{
		"missing url":     {"sas_token": "sig=x"},
		"missing sas":     {"container_url": "https://a.blob.core.windows.net/c"},
		"no container":    {"container_url": "https://a.blob.core.windows.net/", "sas_token": "sig=x"},
		"nested path":     {"container_url": "https://a.blob.core.windows.net/c/d", "sas_token": "sig=x"},
		"plain http":      {"container_url": "http://a.blob.core.windows.net/c", "sas_token": "sig=x"},
		"sas twice":       {"container_url": "https://a.blob.core.windows.net/c?sig=x", "sas_token": "sig=y"},
		"sas without sig": {"container_url": "https://a.blob.core.windows.net/c", "sas_token": "sp=r"},
	} {
		if _, err := newAzureBlobClient(cfg); err == nil {
			t.Errorf("%s: want error", name)
		} else if strings.Contains(err.Error(), "sig=") {
			t.Errorf("%s: error leaks SAS: %v", name, err)
		}
	}
}

func TestAzureBlobFingerprintOptsOutOfSkipFastPath(t *testing.T) {
	fp, err := fingerprintAzureBlob(context.Background(), Config{"container_url": "https://a.blob.core.windows.net/c", "sas_token": "sig=one"})
	if err != nil || fp != "" {
		t.Fatalf("want empty fingerprint (per-blob state drives incremental), got %q, %v", fp, err)
	}
	if _, err := fingerprintAzureBlob(context.Background(), Config{"container_url": "https://a.blob.core.windows.net/c"}); err == nil {
		t.Fatal("fingerprint should still validate config")
	}
}
