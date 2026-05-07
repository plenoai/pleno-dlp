package mixpanel

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyAccount = "mycompanyabc.AbCdEfGh" // 10+ lowercase + dot + 8 base62
const dummySecret = "0123456789abcdef0123456789abcdef"

func TestFromData_Pair(t *testing.T) {
	body := []byte("# mixpanel\nMIXPANEL_SERVICE_ACCOUNT=" + dummyAccount + "\nMIXPANEL_SECRET=" + dummySecret)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyAccount {
		t.Fatalf("Raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("RawV2 mismatch: %q", res[0].RawV2)
	}
}

func TestFromData_AccountOnly_NoSecret(t *testing.T) {
	body := []byte("# mixpanel\nACCOUNT=" + dummyAccount)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if len(res[0].RawV2) != 0 {
		t.Fatalf("RawV2 should be empty: %q", res[0].RawV2)
	}
	if res[0].Verified {
		t.Fatal("single-key match must not be verified")
	}
}

func TestFromData_NoKeyword_DoesNotMatch(t *testing.T) {
	// slug.id shape without "mixpanel" → must skip.
	body := []byte("hostname=" + dummyAccount + " secret=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyAccount)
	if r == dummyAccount {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "mycomp") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(dummyAccount+":"+dummySecret))
		if r.Header.Get("Authorization") != want {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyAccount+":"+dummySecret)
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

	v, err := Scanner{}.Verify(context.Background(), dummyAccount+":"+dummySecret)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}
