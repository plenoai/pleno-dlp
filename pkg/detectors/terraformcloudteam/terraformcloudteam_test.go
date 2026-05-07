package terraformcloudteam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const dummy = "abcdefghij1234.atlasv1." +
	"ABCDEFGHIJabcdefghij0123456789-_ABCDEFGHIJabcdefghij0123456789-_"

func TestFromData_TeamScope(t *testing.T) {
	body := "TFE_TEAM_TOKEN=" + dummy
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if got := res[0].ExtraData["scope"]; got != "team" {
		t.Fatalf("expected scope=team, got %q", got)
	}
}

func TestFromData_NoTeamKeyword(t *testing.T) {
	// Without a team keyword nearby, this detector defers to terraformcloud.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("TFE_TOKEN="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without team keyword, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
