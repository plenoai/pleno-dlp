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

func TestJiraIncrementalScanEmitsOnlyChangedObjects(t *testing.T) {
	description := jiraADF("old description")
	comment := jiraADF("keep comment")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/3/search" {
			t.Fatalf("unexpected Jira API path: %s", r.URL.String())
		}
		writeJSON(t, w, map[string]any{
			"startAt":    0,
			"maxResults": 50,
			"total":      1,
			"issues": []map[string]any{{
				"key": "ABC-1",
				"fields": map[string]any{
					"summary":     "summary",
					"description": description,
					"comment": map[string]any{
						"comments": []map[string]any{{
							"id":   "10001",
							"body": comment,
						}},
					},
				},
			}},
		})
	}))
	defer srv.Close()

	cfg := Config{"token": "jira-token", "api_base": srv.URL, "project": "ABC"}
	var first []string
	if err := scanJira(context.Background(), cfg, func(data []byte, _ sources.Metadata) error {
		first = append(first, string(data))
		return nil
	}); err != nil {
		t.Fatalf("first scanJira: %v", err)
	}
	sort.Strings(first)
	if got, want := strings.Join(first, ","), "keep comment,old description"; got != want {
		t.Fatalf("first emitted %q, want %q", got, want)
	}
	previous := cfg[configKeyIncrementalNextState]
	if previous == "" {
		t.Fatal("first scan did not persist incremental state")
	}
	if !json.Valid([]byte(previous)) {
		t.Fatalf("invalid incremental state: %s", previous)
	}

	description = jiraADF("new description")
	cfg[configKeyIncrementalPreviousState] = previous
	delete(cfg, configKeyIncrementalNextState)
	var second []string
	if err := scanJira(context.Background(), cfg, func(data []byte, _ sources.Metadata) error {
		second = append(second, string(data))
		return nil
	}); err != nil {
		t.Fatalf("second scanJira: %v", err)
	}
	if got, want := strings.Join(second, ","), "new description"; got != want {
		t.Fatalf("second emitted %q, want only changed object %q", got, want)
	}
}

func jiraADF(text string) map[string]any {
	return map[string]any{
		"type":    "doc",
		"version": 1,
		"content": []map[string]any{{
			"type": "paragraph",
			"content": []map[string]string{{
				"type": "text",
				"text": text,
			}},
		}},
	}
}
