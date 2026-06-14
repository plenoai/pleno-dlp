//go:build detector_unit

package databricks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummy = "dapi0123456789abcdef0123456789abcdef"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("DATABRICKS_TOKEN="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_HostCapture(t *testing.T) {
	body := "host=acme.cloud.databricks.com\ntoken=" + dummy
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if got := res[0].ExtraData["host"]; got != "acme.cloud.databricks.com" {
		t.Fatalf("expected host capture, got %q", got)
	}
}

func TestFromData_Negative(t *testing.T) {
	// Bare 32-hex is rejected — no `dapi` prefix.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("md5=0123456789abcdef0123456789abcdef"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "dapi0123") {
		t.Fatalf("missing prefix: %q", r)
	}
}

// withAPIBase points apiBase at a test server for the duration of fn.
func withAPIBase(url string, fn func()) {
	old := apiBase
	apiBase = url
	defer func() { apiBase = old }()
	fn()
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/2.0/clusters/list" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("Authorization mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	withAPIBase(srv.URL, func() {
		v, err := Scanner{}.Verify(context.Background(), dummy)
		if err != nil {
			t.Fatalf("Verify err: %v", err)
		}
		if !v {
			t.Fatal("expected verified=true on 200")
		}
	})
}

func TestVerify_Unauthorized(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		withAPIBase(srv.URL, func() {
			v, err := Scanner{}.Verify(context.Background(), dummy)
			if err != nil {
				t.Fatalf("code %d: unexpected err: %v", code, err)
			}
			if v {
				t.Fatalf("code %d: expected verified=false", code)
			}
		})
		srv.Close()
	}
}

func TestVerify_TransientRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	withAPIBase(srv.URL, func() {
		v, err := Scanner{}.Verify(context.Background(), dummy)
		if v {
			t.Fatal("429 must not verify")
		}
		if err == nil {
			t.Fatal("429 must surface a transient error, not a rejection")
		}
	})
}

func TestVerify_TransientServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	withAPIBase(srv.URL, func() {
		v, err := Scanner{}.Verify(context.Background(), dummy)
		if v {
			t.Fatal("500 must not verify")
		}
		if err == nil {
			t.Fatal("500 must surface a transient error, not a rejection")
		}
	})
}

func TestVerify_NoHostNoOp(t *testing.T) {
	// apiBase empty and no chunk host -> no-op (false, nil), no probe.
	withAPIBase("", func() {
		v, err := Scanner{}.Verify(context.Background(), dummy)
		if v || err != nil {
			t.Fatalf("expected no-op (false, nil), got (%v, %v)", v, err)
		}
	})
}

func TestFromData_VerifyUsesChunkHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/2.0/clusters/list" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Strip scheme so the chunk host looks like a bare workspace domain; the
	// detector promotes it to https. We point that derivation at the test
	// server by stripping "http://" and letting resolveHost re-add a scheme —
	// but since httptest serves http, drive verification through apiBase here
	// and assert FromData wires verify through end-to-end.
	withAPIBase(srv.URL, func() {
		body := []byte("host=acme.cloud.databricks.com\ntoken=" + dummy)
		res, err := Scanner{}.FromData(context.Background(), true, body)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if len(res) != 1 {
			t.Fatalf("expected 1, got %d", len(res))
		}
		if !res[0].Verified {
			t.Fatalf("expected Verified=true, got false (err=%v)", res[0].VerificationErr)
		}
	})
}
