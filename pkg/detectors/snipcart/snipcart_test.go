//go:build detector_unit

package snipcart

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// 75-char high-entropy token of [0-9A-Za-z_], matching the documented upstream
// Snipcart secret-key shape. Bare literal (not in an auth-header context) to
// stay clear of the gitleaks pre-commit hook.
const dummyToken = "OhbVrpoiVgRV5IfLBcbfnoGMbJmTPSIAoCLrZ3aWZkSBvrjn9Wvgfygw2wMqZcUDIh_7yfJs1ON"

// lowEntropyToken is exactly 75 chars but structurally repetitive — it clears
// the charset/length regex yet must be culled by the entropy floor.
const lowEntropyToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Snipcart {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("SNIPCART_API_KEY=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("API_KEY=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without snipcart keyword, got %d", len(res))
	}
}

// A bare "snipcart" mention near a generic 75-char token (no assignment-style
// reference) must no longer arm: the radius-64 arm regex replaces the old
// radius-256 Contains gate.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("the snipcart cdn script lives at example.com see token " + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare keyword without arm reference, got %d", len(res))
	}
}

// A structurally repetitive 75-char string near a real arm reference clears the
// length/charset regex but must be culled by the entropy floor.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("SNIPCART_API_KEY=" + lowEntropyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy token, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, _, _ := r.BasicAuth()
		if u != dummyToken {
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
