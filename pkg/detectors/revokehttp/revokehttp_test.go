package revokehttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDoBoundsBodyAndSetsHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-T") != "v" {
			t.Errorf("header not applied")
		}
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(strings.Repeat("a", MaxBody+10)))
	}))
	defer srv.Close()
	resp, err := Do(context.Background(), srv.Client(), http.MethodGet, srv.URL, map[string]string{"X-T": "v"}, nil)
	if err != nil || resp.Status != http.StatusTeapot || len(resp.Body) != MaxBody {
		t.Fatalf("resp=%d len=%d err=%v", resp.Status, len(resp.Body), err)
	}
}

func TestFingerprintDoesNotLeak(t *testing.T) {
	fp := Fingerprint("hf_secretvalue")
	if strings.Contains(fp, "secret") || !strings.HasPrefix(fp, "sha256:") || len(fp) != len("sha256:")+12 {
		t.Fatalf("fp = %q", fp)
	}
	if Fingerprint("a") == Fingerprint("b") {
		t.Fatal("collision")
	}
}

func TestStatusError(t *testing.T) {
	if !strings.Contains(StatusError("p", 503).Error(), "503") {
		t.Fatal("status missing")
	}
}
