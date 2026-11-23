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

func TestScanSlackSearchMessagesAndFiles(t *testing.T) {
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/search.messages":
			if r.URL.Query().Get("query") != "password in:#ops" {
				t.Errorf("query = %q", r.URL.Query().Get("query"))
			}
			if r.URL.Query().Get("page") == "1" {
				_, _ = w.Write([]byte(`{"ok":true,"messages":{"matches":[{"ts":"1.1","text":"pw=one","channel":{"id":"C1"}}],"paging":{"page":1,"pages":2}}}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true,"messages":{"matches":[{"ts":"2.2","text":"pw=two","channel":{"id":"C2"}}],"paging":{"page":2,"pages":2}}}`))
		case "/api/search.files":
			_, _ = w.Write([]byte(`{"ok":true,"files":{"matches":[{"id":"F1","name":"a.env","timestamp":5,"channels":["C1"],"url_private_download":"` + srvURL + `/dl/a"},{"id":"F2","name":"x","url_private_download":"https://attacker.example/x"}],"paging":{"page":1,"pages":1}}}`))
		case "/dl/a":
			_, _ = w.Write([]byte("FILE=secret"))
		default:
			t.Errorf("unexpected %s", r.URL)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL
	var got []string
	cfg := Config{"token": "xoxp-t", "api_base": srv.URL, "query": "password in:#ops"}
	err := scanSlack(context.Background(), cfg, func(data []byte, meta sources.Metadata) error {
		got = append(got, meta.Slack.Channel+"|"+string(data))
		return nil
	})
	var de *engine.DegradedError
	if !errors.As(err, &de) || de.Total != 1 || !strings.Contains(de.Failures[0].Source, "F2") {
		t.Fatalf("want foreign-download gap for F2, got %v", err)
	}
	sort.Strings(got)
	if strings.Join(got, ";") != "C1|FILE=secret;C1|pw=one;C2|pw=two" {
		t.Fatalf("got %q", got)
	}

	cfg["max_results"] = "1"
	got = nil
	_ = scanSlack(context.Background(), cfg, func(data []byte, meta sources.Metadata) error {
		got = append(got, string(data))
		return nil
	})
	sort.Strings(got)
	if strings.Join(got, ";") != "FILE=secret;pw=one" {
		t.Fatalf("max_results=1 got %q", got)
	}
}

func TestScanSlackSearchRejectsBotTokenWithHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"error":"not_allowed_token_type"}`))
	}))
	defer srv.Close()
	err := scanSlack(context.Background(), Config{"token": "xoxb-t", "api_base": srv.URL, "query": "x"}, func([]byte, sources.Metadata) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "user token") {
		t.Fatalf("want user-token hint, got %v", err)
	}
	if err := scanSlack(context.Background(), Config{"token": "t", "api_base": srv.URL, "query": "x", "channel": "C"}, func([]byte, sources.Metadata) error { return nil }); err == nil {
		t.Fatal("query+channel accepted")
	}
}
