//go:build detector_unit

package greenhouse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "abcdef0123456789abcdef0123456789abcdef0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Greenhouse {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("GREENHOUSE_API_KEY=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

// TestFromData_BareApiEnvVar locks in recall for the bare `GREENHOUSE_API`
// env-var assignment form (no token/key/secret suffix). This was the
// pre-hardening positive shape; the arm regex must keep matching it so
// credentials assigned to GREENHOUSE_API are not silently dropped.
func TestFromData_BareApiEnvVar(t *testing.T) {
	body := []byte("GREENHOUSE_API=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1 for GREENHOUSE_API env-var form, got 0")
	}
}

// TestFromData_DocumentedShape covers the authoritatively documented token
// shape: a 32-char lowercase hex string (developers.greenhouse.io example
// a7183e1b7e9ab09b8a5cfa87d1934c3c) referenced via an assignment key.
func TestFromData_DocumentedShape(t *testing.T) {
	body := []byte("greenhouse_api_token = a7183e1b7e9ab09b8a5cfa87d1934c3c")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1 for documented 32-hex token, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without greenhouse keyword, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm is the FP regression now rejected: a generic
// high-entropy hex run sitting near a bare "greenhouse" word (a doc link, a
// host reference) but with no `greenhouse…(token|key|secret)` assignment
// anchor must no longer match. Under the old radius-256 strings.Contains
// gate this fired; under the arm-regex gate it must not.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("see https://harvest.greenhouse.io/docs and config " + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword-without-arm FP shape, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected is the second FP regression: a 32+ char
// hex run that is a padded placeholder (repeated nibble) clears the hex
// regex and the arm gate but must be culled by the entropy floor.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("greenhouse_api_key = 00000000000000000000000000000000")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy padded hex, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _, ok := r.BasicAuth()
		if !ok || u != dummyToken {
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

func TestVerify_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummyToken)
	if v {
		t.Fatal("expected verified=false on 5xx")
	}
}
