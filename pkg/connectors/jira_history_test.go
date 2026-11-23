package connectors

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestJiraFullCommentsAndChangelog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/api/3/search":
			writeJSON(t, w, map[string]any{"total": 2, "issues": []map[string]any{
				{"key": "ABC-1", "fields": map[string]any{"comment": map[string]any{"total": 2, "comments": []map[string]any{{"id": "1", "body": jiraADF("embedded")}}}}},
				{"key": "ABC-2", "fields": map[string]any{}},
			}})
		case "/rest/api/3/issue/ABC-1/comment":
			if r.URL.Query().Get("startAt") == "0" {
				writeJSON(t, w, map[string]any{"total": 2, "comments": []map[string]any{{"id": "1", "body": jiraADF("embedded")}}})
				return
			}
			writeJSON(t, w, map[string]any{"total": 2, "comments": []map[string]any{{"id": "2", "body": jiraADF("paged comment")}}})
		case "/rest/api/3/issue/ABC-1/changelog":
			if r.URL.Query().Get("startAt") == "0" {
				writeJSON(t, w, map[string]any{"total": 2, "isLast": false, "values": []map[string]any{{"id": "h1", "items": []map[string]any{{"field": "description", "fromString": "old secret", "toString": "redacted"}}}}})
				return
			}
			writeJSON(t, w, map[string]any{"total": 2, "isLast": true, "values": []map[string]any{{"id": "h2", "items": []map[string]any{{"field": "status"}}}}})
		case "/rest/api/3/issue/ABC-2/changelog":
			http.Error(w, "forbidden", http.StatusForbidden)
		default:
			t.Fatalf("unexpected %s", r.URL)
		}
	}))
	defer srv.Close()
	var got []string
	err := scanJira(context.Background(), Config{"token": "t", "api_base": srv.URL, "project": "ABC", "include_changelog": "true"}, func(data []byte, meta sources.Metadata) error {
		got = append(got, meta.Jira.IssueKey+"|"+meta.Jira.Part+"|"+string(data))
		return nil
	})
	var de *engine.DegradedError
	if !errors.As(err, &de) || de.Total != 1 || de.Failures[0].Source != "jira:ABC-2:changelog" {
		t.Fatalf("want ABC-2 changelog gap, got %v", err)
	}
	sort.Strings(got)
	want := "ABC-1|changelog:h1|description: old secret\ndescription: redacted;ABC-1|comment:1|embedded;ABC-1|comment:2|paged comment"
	if strings.Join(got, ";") != want {
		t.Fatalf("got %q", got)
	}
}

func TestJiraMaxResultsCapsIssues(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"total": 2, "issues": []map[string]any{
			{"key": "A-1", "fields": map[string]any{"summary": "one"}},
			{"key": "A-2", "fields": map[string]any{"summary": "two"}},
		}})
	}))
	defer srv.Close()
	var got []string
	if err := scanJira(context.Background(), Config{"token": "t", "api_base": srv.URL, "project": "A", "max_results": "1"}, func(d []byte, _ sources.Metadata) error {
		got = append(got, string(d))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "one" {
		t.Fatalf("got %v", got)
	}
}
