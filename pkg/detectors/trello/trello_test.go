//go:build detector_unit

package trello

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyKey = "0123456789abcdef0123456789abcdef"
const dummyToken = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

func TestFromData_Pair(t *testing.T) {
	body := []byte("# trello\nTRELLO_KEY=" + dummyKey + "\nTRELLO_TOKEN=" + dummyToken)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyKey {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummyToken {
		t.Fatalf("rawv2 mismatch: %q", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("md5="+dummyKey+"\nsha256="+dummyToken))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_KeyWithoutToken(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("# trello\nKEY="+dummyKey))
	if len(res) != 0 {
		t.Fatalf("expected 0 without companion token, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyKey)
	if r == dummyKey {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "01234567") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != dummyKey || r.URL.Query().Get("token") != dummyToken {
			t.Errorf("query mismatch: %v", r.URL.RawQuery)
		}
		if r.URL.Path != "/1/members/me" {
			t.Errorf("path: %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummyToken)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, _ := Scanner{}.Verify(context.Background(), dummyKey+":"+dummyToken)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummyToken)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
