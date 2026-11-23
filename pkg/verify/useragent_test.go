package verify

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserAgentSuffix(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.UserAgent())
	}))
	defer srv.Close()
	t.Cleanup(func() { _ = SetUserAgentSuffix("") })
	if err := SetUserAgentSuffix("acme-sec/1 (+ops@example.com)"); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("User-Agent", "pleno-dlp/okta")
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatal(err)
	}
	if _, err := (&http.Client{}).Get(srv.URL); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("User-Agent") != "pleno-dlp/okta" {
		t.Fatal("caller request mutated")
	}
	_ = SetUserAgentSuffix("")
	if _, err := http.Get(srv.URL); err != nil {
		t.Fatal(err)
	}
	want := []string{"pleno-dlp/okta acme-sec/1 (+ops@example.com)", "pleno-dlp acme-sec/1 (+ops@example.com)", "Go-http-client/1.1"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

func TestValidateUserAgentSuffix(t *testing.T) {
	for _, bad := range []string{"a\r\nX-Evil: 1", "tab\there", string(make([]byte, 200))} {
		if ValidateUserAgentSuffix(bad) == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
