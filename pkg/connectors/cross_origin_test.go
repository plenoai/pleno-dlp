package connectors

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// TestConnectorsRefuseForeignOriginLinks pins #865: every credentialed API
// client refuses absolute URLs (pagination "next" links, object links)
// that leave its configured origin, so the token never reaches them.
func TestConnectorsRefuseForeignOriginLinks(t *testing.T) {
	var hits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{}")
	}))
	t.Cleanup(evil.Close)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{}")
	}))
	t.Cleanup(api.Close)
	target := evil.URL + "/api/v4/projects?page=2"
	ctx := context.Background()
	body := func(r *http.Response, err error) error {
		if r != nil {
			r.Body.Close()
		}
		return err
	}
	cases := map[string]func() error{
		"gitlab": func() error { return body(newGitLabClient(api.URL, "glpat-x").do(ctx, http.MethodGet, target, nil)) },
		"gitea":  func() error { return body(newGiteaClient(api.URL, "tok").do(ctx, http.MethodGet, target, nil)) },
		"bitbucket": func() error {
			return body(newBitbucketClient(api.URL, "", "", "tok").do(ctx, http.MethodGet, target, nil))
		},
		"slack":       func() error { return body(newSlackClient(api.URL, "xoxb-x").do(ctx, http.MethodGet, target, nil)) },
		"notion":      func() error { return body(newNotionClient(api.URL, "tok").do(ctx, http.MethodGet, target, nil)) },
		"huggingface": func() error { return body(newHFClient(api.URL, "tok").do(ctx, http.MethodGet, target, nil)) },
		"confluence": func() error {
			return body(newConfluenceClient(api.URL, "a@b", "tok").do(ctx, http.MethodGet, target, nil))
		},
		"onedev": func() error { return newOneDevClient(api.URL, "tok").getJSON(ctx, target, nil) },
		"pagure": func() error { return newPagureClient(api.URL, "tok").getJSON(ctx, target, nil) },
		"slack-download": func() error {
			_, err := newSlackClient(api.URL, "xoxb-x").download(ctx, target)
			return err
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			err := call()
			if err == nil || !strings.Contains(err.Error(), "foreign origin") {
				t.Fatalf("err = %v, want foreign-origin refusal", err)
			}
		})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("foreign origin received %d credentialed requests", n)
	}
	// Same-origin absolute links keep working.
	if err := body(newGitLabClient(api.URL, "glpat-x").do(ctx, http.MethodGet, api.URL+"/api/v4/projects?page=2", nil)); err != nil {
		t.Fatalf("same-origin link: %v", err)
	}
}

func TestSlackDownloadAllowsSlackFileHost(t *testing.T) {
	c := newSlackClient("", "xoxb-x")
	if err := c.downloadAllowed("https://files.slack.com/files-pri/T1-F1/download/a.txt"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"http://files.slack.com/x", "https://files.slack.com.evil.test/x", "https://evilslack.com/x"} {
		if c.downloadAllowed(bad) == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
