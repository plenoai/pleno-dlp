//go:build detector_unit

package mercurybank

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummyToken mirrors the documented Mercury shape:
//
//	secret-token:mercury_<env>_<type>_<body>_yrucrem
//
// (see https://docs.mercury.com/reference/getting-started-with-your-api). It is
// a synthetic body — never a real credential — and is kept as a bare literal,
// never embedded in an Authorization-header string, to satisfy the leak hook.
const dummyToken = "secret-token:mercury_production_wma_24SCp4G81X3yHL4Wq8FgzuaP9ye3VKf2mgTDctXyRg5HY_yrucrem"

// dummySandboxToken exercises the sandbox environment alternation.
const dummySandboxToken = "secret-token:mercury_sandbox_wma_9bQ7Xm2VpLkR4tNzWcEgHs6Yfd3Ja1Uo_yrucrem"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.MercuryBank {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("mercury_api_key=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].Raw) != dummyToken {
		t.Fatalf("captured token mismatch: got %q", res[0].Raw)
	}
}

func TestFromData_FoundSandbox(t *testing.T) {
	body := []byte("config: " + dummySandboxToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 sandbox token, got %d", len(res))
	}
	if string(res[0].Raw) != dummySandboxToken {
		t.Fatalf("captured sandbox token mismatch: got %q", res[0].Raw)
	}
}

// TestFromData_GenericHighEntropyRejected is the FP regression for the shape the
// previous bare [A-Za-z0-9]{32,120} + radius-256 substring gate falsely matched:
// a generic high-entropy alphanumeric run sitting near the word "mercury" but
// lacking the documented secret-token:mercury_ prefix. The prefix anchor must
// reject it.
func TestFromData_GenericHighEntropyRejected(t *testing.T) {
	body := []byte("mercury_api_key=abcdefghijklmnopqrstuvwxyzABCDEF1234567890XYZ")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected generic high-entropy run near 'mercury' to be rejected, got %d", len(res))
	}
}

// TestFromData_NoPrefixRejected guards against a long token that has every part
// except the mandatory secret-token: prefix.
func TestFromData_NoPrefixRejected(t *testing.T) {
	body := []byte("mercury_production_wma_24SCp4G81X3yHL4Wq8FgzuaP9ye3VKf2mgTDctXyRg5HY_yrucrem")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected token without secret-token: prefix to be rejected, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=abcdefghijklmnopqrstuvwxyzABCDEF12")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without mercury token shape, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte(dummyToken + "\n" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyToken {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyToken)
	if err != nil || !v {
		t.Fatalf("expected verified=true: err=%v v=%v", err, v)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyToken)
	if v {
		t.Fatal("expected verified=false")
	}
}
