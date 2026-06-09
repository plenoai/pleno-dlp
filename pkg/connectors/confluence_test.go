package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestConfluenceIncrementalScanEmitsOnlyChangedObjects(t *testing.T) {
	pageBody := "old page"
	commentBody := "keep comment"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/rest/api/content":
			writeJSON(t, w, map[string]any{
				"results": []map[string]any{{
					"id":    "123",
					"type":  "page",
					"title": "Runbook",
					"space": map[string]string{"key": "SEC", "name": "Security"},
					"body": map[string]any{
						"storage": map[string]string{"value": pageBody},
					},
					"_links": map[string]string{"webui": "/wiki/spaces/SEC/pages/123"},
				}},
				"_links": map[string]string{},
			})
		case strings.Contains(r.URL.Path, "/rest/api/content/123/child/comment"):
			location := r.URL.Query().Get("location")
			if location == "footer" {
				writeJSON(t, w, map[string]any{
					"results": []map[string]any{{
						"id":   "c1",
						"type": "comment",
						"body": map[string]any{
							"storage": map[string]string{"value": commentBody},
						},
						"extensions": map[string]string{"location": "footer"},
					}},
					"_links": map[string]string{},
				})
				return
			}
			writeJSON(t, w, map[string]any{"results": []any{}, "_links": map[string]string{}})
		default:
			t.Fatalf("unexpected Confluence API path: %s", r.URL.String())
		}
	}))
	defer srv.Close()

	cfg := Config{"token": "conf-token", "api_base": srv.URL}
	var first []string
	if err := scanConfluence(context.Background(), cfg, func(data []byte, _ sources.Metadata) error {
		first = append(first, string(data))
		return nil
	}); err != nil {
		t.Fatalf("first scanConfluence: %v", err)
	}
	sort.Strings(first)
	if got, want := strings.Join(first, ","), "# Runbook\n\nold page,keep comment"; got != want {
		t.Fatalf("first emitted %q, want %q", got, want)
	}
	previous := cfg[configKeyIncrementalNextState]
	if previous == "" {
		t.Fatal("first scan did not persist incremental state")
	}
	if !json.Valid([]byte(previous)) {
		t.Fatalf("invalid incremental state: %s", previous)
	}

	pageBody = "new page"
	cfg[configKeyIncrementalPreviousState] = previous
	delete(cfg, configKeyIncrementalNextState)
	var second []string
	if err := scanConfluence(context.Background(), cfg, func(data []byte, _ sources.Metadata) error {
		second = append(second, string(data))
		return nil
	}); err != nil {
		t.Fatalf("second scanConfluence: %v", err)
	}
	if got, want := strings.Join(second, ","), "# Runbook\n\nnew page"; got != want {
		t.Fatalf("second emitted %q, want only changed page %q", got, want)
	}
}
