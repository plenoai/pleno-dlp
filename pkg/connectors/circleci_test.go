package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestScanCircleCI(t *testing.T) {
	const testToken = "test-token"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Circle-Token") != testToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api/v1.1/projects":
			json.NewEncoder(w).Encode([]map[string]any{
				{
					"vcs_type": "github",
					"username": "testorg",
					"reponame": "myrepo",
				},
			})
		case r.URL.Path == "/api/v2/project/github/testorg/myrepo/pipeline":
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{"id": "pipe-1", "number": 42},
				},
			})
		case r.URL.Path == "/api/v2/pipeline/pipe-1/config":
			json.NewEncoder(w).Encode(map[string]any{
				"source": "version: 2.1\njobs:\n  build:\n    docker:\n      - image: cimg/go:1.21\n    steps:\n      - run: echo SECRET_KEY=hunter2\n",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	var chunks []string
	emit := func(data []byte, meta sources.Metadata) error {
		chunks = append(chunks, string(data))
		if meta.SIEM == nil || meta.SIEM.Provider != "circleci" {
			t.Error("expected SIEM metadata with provider=circleci")
		}
		if meta.SIEM.Index != "github/testorg/myrepo" {
			t.Errorf("expected index=github/testorg/myrepo, got %q", meta.SIEM.Index)
		}
		return nil
	}

	err := scanCircleCI(context.Background(), Config{
		"token":    testToken,
		"base_url": ts.URL,
	}, emit)
	if err != nil {
		t.Fatalf("scanCircleCI: %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk (pipeline config), got %d: %v", len(chunks), chunks)
	}
	if !strings.Contains(chunks[0], "hunter2") {
		t.Errorf("expected config chunk to contain test secret")
	}
}

func TestScanCircleCI_MissingToken(t *testing.T) {
	err := scanCircleCI(context.Background(), Config{}, nil)
	if err == nil || !strings.Contains(err.Error(), "token") {
		t.Errorf("expected token error, got: %v", err)
	}
}

func TestVerifyCircleCI(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/me" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Circle-Token") == "valid-token" {
			fmt.Fprintln(w, `{"id":"user-1","login":"testuser"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	ok, err := verifyCircleCI(context.Background(), Config{"base_url": ts.URL}, "valid-token")
	if err != nil || !ok {
		t.Errorf("expected verified, got ok=%v err=%v", ok, err)
	}
	ok, err = verifyCircleCI(context.Background(), Config{"base_url": ts.URL}, "bad-token")
	if err != nil || ok {
		t.Errorf("expected not verified, got ok=%v err=%v", ok, err)
	}
}

func TestCircleCIConnectorRegistered(t *testing.T) {
	c, ok := Get("circleci")
	if !ok {
		t.Fatal("circleci connector not registered")
	}
	if c.Scan == nil {
		t.Error("circleci connector has nil Scan")
	}
	if c.Verify == nil {
		t.Error("circleci connector has nil Verify")
	}
	if c.Fingerprint == nil {
		t.Error("circleci connector has nil Fingerprint")
	}
	if c.SourceType != sources.SourceCircleCI {
		t.Errorf("expected SourceCircleCI, got %v", c.SourceType)
	}
}

func TestCircleCISourceTypeString(t *testing.T) {
	if got := sources.SourceCircleCI.String(); got != "circleci" {
		t.Errorf("SourceCircleCI.String()=%q, want %q", got, "circleci")
	}
}
