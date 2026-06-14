//go:build detector_unit

package zoom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyID = "AbCdEf0123456789ABCDEF"               // 22 chars
const dummySecret = "qwertyuiopasdfghjklzxcvbnm123456" // 32 chars

func TestFromData_Pair(t *testing.T) {
	body := []byte("# zoom oauth\nZOOM_CLIENT_ID=" + dummyID + "\nZOOM_CLIENT_SECRET=" + dummySecret)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("expected at least one hit")
	}
	// Find the id-paired hit.
	var found bool
	for _, r := range res {
		if string(r.Raw) == dummyID && string(r.RawV2) == dummySecret {
			found = true
			if r.Severity != detectors.SeverityCritical {
				t.Fatalf("expected SeverityCritical")
			}
		}
	}
	if !found {
		t.Fatalf("expected pair {%q,%q} not found in %v", dummyID, dummySecret, res)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("X=" + dummyID + "\nY=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "AbCdEf01") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != dummyID || p != dummySecret {
			t.Errorf("basic mismatch: %q %q ok=%v", u, p, ok)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"x"}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
