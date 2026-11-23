package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func requireGaps(t *testing.T, err error, want ...string) {
	t.Helper()
	var de *engine.DegradedError
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want DegradedError", err)
	}
	seen := map[string]bool{}
	for _, f := range de.Failures {
		seen[f.Source] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("missing gap %q in %v", w, seen)
		}
	}
	if de.Total != len(want) {
		t.Errorf("Total = %d, want %d (%v)", de.Total, len(want), seen)
	}
}

// Per-file fetch failures in Bitbucket are coverage gaps and stay out of the
// next checkpoint (#882).
func TestBitbucketFileFetchFailureIsCoverageGap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2.0/repositories/acme/widget":
			writeJSON(t, w, bitbucketRepo("acme", "widget", "main"))
		case "/2.0/repositories/acme/widget/src/main/":
			writeJSON(t, w, bitbucketPaginatedSrc{Values: []bitbucketSrcEntry{
				bitbucketEntry("ok.go", "commit_file", 4, "h1"),
				bitbucketEntry("denied.go", "commit_file", 4, "h2"),
			}})
		case "/2.0/repositories/acme/widget/src/main/ok.go":
			_, _ = w.Write([]byte("okay"))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := Config{"token": "bb-test", "repo": "acme/widget", "api_base": srv.URL}
	err := scanBitbucket(context.Background(), cfg, func([]byte, sources.Metadata) error { return nil })
	requireGaps(t, err, bitbucketFileSource("acme", "widget", "main", "denied.go"))
	var next bitbucketIncrementalState
	if err := json.Unmarshal([]byte(cfg[configKeyIncrementalNextState]), &next); err != nil {
		t.Fatal(err)
	}
	files := next.Repos["acme/widget"].Files
	if _, ok := files["ok.go"]; !ok {
		t.Error("covered file missing from checkpoint")
	}
	if _, ok := files["denied.go"]; ok {
		t.Error("failed file recorded in checkpoint; it would never be retried")
	}
}

func TestGitLabBlobFetchFailureIsCoverageGap(t *testing.T) {
	proj := gitlabProjectRef{ID: 1, PathWithNS: "acme/widget", DefaultBranch: "main"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/projects/acme/widget", "/projects/acme%2Fwidget":
			writeJSON(t, w, proj)
		case "/projects/1/repository/tree":
			writeJSON(t, w, []gitlabTreeEntry{{Path: "ok.go", Type: "blob", ID: "b1"}, {Path: "denied.go", Type: "blob", ID: "b2"}})
		case "/projects/1/repository/files/ok.go/raw":
			_, _ = w.Write([]byte("okay"))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := Config{"token": "glpat-test", "project": "acme/widget", "api_base": srv.URL}
	err := scanGitLab(context.Background(), cfg, func([]byte, sources.Metadata) error { return nil })
	requireGaps(t, err, gitlabBlobSource(proj, "denied.go"))
	var next gitlabIncrementalState
	if err := json.Unmarshal([]byte(cfg[configKeyIncrementalNextState]), &next); err != nil {
		t.Fatal(err)
	}
	if _, ok := next.Projects["acme/widget"].Blobs["denied.go"]; ok {
		t.Error("failed blob recorded in checkpoint")
	}
	if _, ok := next.Projects["acme/widget"].Blobs["ok.go"]; !ok {
		t.Error("covered blob missing from checkpoint")
	}
}

func TestRedashQueryFailureIsCoverageGap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	cfg := Config{"api_key": "k", "host": srv.URL, "query_ids": "7"}
	err := scanRedash(context.Background(), cfg, func([]byte, sources.Metadata) error { return nil })
	requireGaps(t, err, "redash/query/7")
	if _, err := fingerprintRedash(context.Background(), cfg); err == nil {
		t.Fatal("fingerprint succeeded despite unreadable query")
	}
}
