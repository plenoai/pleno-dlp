package connectors

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestHuggingFaceCloneURLByType(t *testing.T) {
	for typ, want := range map[string]string{
		"model":   "https://hf.test/o/n.git",
		"dataset": "https://hf.test/datasets/o/n.git",
		"space":   "https://hf.test/spaces/o/n.git",
	} {
		if got := hfCloneURL("https://hf.test/", typ, "o", "o/n"); got != want {
			t.Errorf("%s: got %q want %q", typ, got, want)
		}
	}
}

func TestParseHFBucket(t *testing.T) {
	cases := map[string]hfBucketTarget{
		"o/b":                                {ID: "o/b"},
		"o/b/tree/x":                         {ID: "o/b", Prefix: "tree/x"},
		"hf://buckets/o/b/dir/":              {ID: "o/b", Prefix: "dir"},
		"https://huggingface.co/buckets/o/b": {ID: "o/b"},
		"https://huggingface.co/buckets/o/b/tree/d/e": {ID: "o/b", Prefix: "d/e"},
	}
	for in, want := range cases {
		got, err := parseHFBucket(in)
		if err != nil || got != want {
			t.Errorf("parseHFBucket(%q) = %+v, %v; want %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"o", "hf://models/o/b", "https://huggingface.co/o/b", "o/b/../c"} {
		if _, err := parseHFBucket(bad); err == nil {
			t.Errorf("parseHFBucket(%q) accepted", bad)
		}
	}
}

// hfBucketServer serves a user "alice" with one bucket alice/data containing
// two files across two Link-paginated tree pages, one broken object, and no
// model/dataset/space repos.
func hfBucketServer(t *testing.T, foreignNext bool) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var foreignHits atomic.Int32
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/api/models", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("author") != "alice" {
			t.Errorf("author = %q", r.URL.Query().Get("author"))
		}
		hfWriteJSON(t, w, []hfRepoRef{})
	})
	mux.HandleFunc("/api/buckets/alice", func(w http.ResponseWriter, r *http.Request) {
		hfWriteJSON(t, w, []map[string]string{{"id": "alice/data"}})
	})
	mux.HandleFunc("/api/buckets/alice/data/tree", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer hf_tok" {
			t.Errorf("missing auth on tree")
		}
		if r.URL.Query().Get("cursor") == "" {
			next := srv.URL + "/api/buckets/alice/data/tree?recursive=true&cursor=2"
			if foreignNext {
				next = "https://evil.test/api/buckets/alice/data/tree?cursor=2"
			}
			w.Header().Set("Link", "<"+next+">; rel=\"next\"")
			hfWriteJSON(t, w, []hfBucketEntry{{Type: "file", Path: "a/config.env", Size: 10}, {Type: "directory", Path: "a"}})
			return
		}
		hfWriteJSON(t, w, []hfBucketEntry{{Type: "file", Path: "b c.txt", Size: 5}, {Type: "file", Path: "broken.bin", Size: 3}})
	})
	mux.HandleFunc("/buckets/alice/data/resolve/", func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/buckets/alice/data/resolve/") {
		case "a/config.env":
			_, _ = w.Write([]byte("SECRET=one"))
		case "b c.txt":
			_, _ = w.Write([]byte("two"))
		default:
			http.Error(w, "nope", http.StatusForbidden)
		}
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &foreignHits
}

func TestHuggingFaceScanUserBuckets(t *testing.T) {
	srv, _ := hfBucketServer(t, false)
	var paths []string
	err := scanHuggingFace(context.Background(), Config{"user": "alice", "token": "hf_tok", "api_base": srv.URL, "repo_types": "model,bucket"}, func(data []byte, meta sources.Metadata) error {
		hf := meta.HuggingFace
		if hf == nil || hf.RepoType != "bucket" || hf.Organization != "alice" || hf.Repository != "data" {
			t.Errorf("bad meta %+v", hf)
		}
		paths = append(paths, hf.Path+"="+string(data))
		return nil
	})
	var de *engine.DegradedError
	if !errors.As(err, &de) || de.Total != 1 || !strings.Contains(de.Failures[0].Source, "broken.bin") {
		t.Fatalf("want one degraded failure for broken.bin, got %v", err)
	}
	sort.Strings(paths)
	if strings.Join(paths, "|") != "a/config.env=SECRET=one|b c.txt=two" {
		t.Fatalf("paths = %v", paths)
	}
}

func TestHuggingFaceBucketRefusesForeignNextLink(t *testing.T) {
	srv, _ := hfBucketServer(t, true)
	var n int
	err := scanHuggingFace(context.Background(), Config{"bucket": "alice/data", "token": "hf_tok", "api_base": srv.URL}, func([]byte, sources.Metadata) error { n++; return nil })
	var de *engine.DegradedError
	if !errors.As(err, &de) || !strings.Contains(de.Failures[0].Err.Error(), "foreign origin") {
		t.Fatalf("want foreign-origin coverage gap, got %v", err)
	}
	if n != 0 {
		t.Fatalf("emitted %d objects from a refused listing", n)
	}
}

func TestHuggingFaceListBucketsNotFoundIsEmpty(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	ids, err := hfListBuckets(context.Background(), newHFClient(srv.URL, ""), "x")
	if err != nil || len(ids) != 0 {
		t.Fatalf("got %v, %v", ids, err)
	}
}

func TestHuggingFaceFingerprintTracksBucketObjects(t *testing.T) {
	srv, _ := hfBucketServer(t, false)
	cfg := Config{"bucket": "alice/data", "api_base": srv.URL, "token": "hf_tok", "user": "alice", "repo_types": "model"}
	a, err := fingerprintHuggingFace(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg["bucket"] = "alice/data/a"
	b, err := fingerprintHuggingFace(context.Background(), cfg)
	if err == nil && a == b {
		t.Fatal("fingerprint ignored bucket scope")
	}
}
