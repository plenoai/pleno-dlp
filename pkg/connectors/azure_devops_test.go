package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func newFakeAzureDevOps(t *testing.T, repos []map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pass, ok := r.BasicAuth(); !ok || pass != "ado-pat" {
			w.WriteHeader(http.StatusNonAuthoritativeInfo) // ADO's sign-in redirect page
			return
		}
		switch r.URL.Path {
		case "/acme/_apis/git/repositories", "/acme/Proj/_apis/git/repositories":
			if r.URL.Query().Get("api-version") == "" {
				http.Error(w, "missing api-version", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"value": repos})
		case "/acme/_apis/projects":
			_, _ = w.Write([]byte(`{"value":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAzureDevOpsScansHistoryIncrementally(t *testing.T) {
	repoDir, commit := newTestGitRepo(t)
	commit("OLD=ado-history-1\n")
	srv := newFakeAzureDevOps(t, []map[string]any{
		{"id": "1", "name": "api", "remoteUrl": repoDir, "project": map[string]any{"name": "Proj"}},
		{"id": "2", "name": "old", "remoteUrl": repoDir, "isDisabled": true, "project": map[string]any{"name": "Proj"}},
	})
	cfg := Config{"token": "ado-pat", "org": "acme", "project": "Proj", "base_url": srv.URL}
	run := func() string {
		t.Helper()
		var got []string
		if err := scanAzureDevOps(context.Background(), cfg, func(data []byte, meta sources.Metadata) error {
			if meta.Forge == nil || meta.Forge.Provider != "azure-devops" || meta.Forge.Repository != "Proj/api" || meta.Forge.Commit == "" {
				t.Errorf("bad forge meta %+v", meta.Forge)
			}
			got = append(got, string(data))
			return nil
		}); err != nil {
			t.Fatalf("scan: %v", err)
		}
		cfg[configKeyIncrementalPreviousState] = cfg[configKeyIncrementalNextState]
		return strings.Join(got, "|")
	}
	if first := run(); !strings.Contains(first, "ado-history-1") {
		t.Fatalf("first scan missed history: %s", first)
	}
	commit("NEW=ado-history-2\n")
	second := run()
	if !strings.Contains(second, "ado-history-2") || strings.Contains(second, "ado-history-1") {
		t.Fatalf("incremental scan = %q, want only the new commit", second)
	}
}

func TestAzureDevOpsCloneFailureIsDegradedAndEmitErrorAborts(t *testing.T) {
	repoDir, commit := newTestGitRepo(t)
	commit("A=1\n")
	srv := newFakeAzureDevOps(t, []map[string]any{
		{"name": "gone", "remoteUrl": repoDir + "-missing", "project": map[string]any{"name": "P"}},
		{"name": "ok", "remoteUrl": repoDir, "project": map[string]any{"name": "P"}},
	})
	var n int
	err := scanAzureDevOps(context.Background(), Config{"token": "ado-pat", "org": "acme", "base_url": srv.URL}, func([]byte, sources.Metadata) error { n++; return nil })
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || degraded.Total != 1 || n == 0 {
		t.Fatalf("want 1 degraded repo and the other scanned, got %v (chunks %d)", err, n)
	}

	sentinel := errors.New("sink closed")
	err = scanAzureDevOps(context.Background(), Config{"token": "ado-pat", "org": "acme", "base_url": srv.URL}, func([]byte, sources.Metadata) error { return sentinel })
	if !errors.Is(err, sentinel) || errors.As(err, &degraded) {
		t.Fatalf("emit error must abort, got %v", err)
	}
}

func TestAzureDevOpsVerifyConfigAndCloneURL(t *testing.T) {
	srv := newFakeAzureDevOps(t, nil)
	if ok, err := verifyAzureDevOps(context.Background(), Config{"org": "acme", "base_url": srv.URL}, "ado-pat"); !ok || err != nil {
		t.Fatalf("good PAT: ok=%v err=%v", ok, err)
	}
	if ok, err := verifyAzureDevOps(context.Background(), Config{"org": "acme", "base_url": srv.URL}, "bad"); ok || err != nil {
		t.Fatalf("bad PAT (203 sign-in page): ok=%v err=%v", ok, err)
	}
	for name, cfg := range map[string]Config{
		"no token":  {"org": "acme"},
		"no org":    {"token": "x"},
		"org path":  {"token": "x", "org": "a/b"},
		"http base": {"token": "x", "org": "a", "base_url": "http://ado.example.com"},
	} {
		if _, err := fingerprintAzureDevOps(context.Background(), cfg); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if fp, err := fingerprintAzureDevOps(context.Background(), Config{"token": "x", "org": "a"}); fp != "" || err != nil {
		t.Fatalf("fingerprint should opt out of the skip fast-path: %q %v", fp, err)
	}
	r := azureDevOpsRepo{RemoteURL: "https://acme@dev.azure.com/acme/Proj/_git/api"}
	if got := r.cloneURL(); got != "https://dev.azure.com/acme/Proj/_git/api" {
		t.Fatalf("cloneURL = %q", got)
	}
}
