//go:build detector_unit

package sapariba

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a 32-char mixed-case alphanumeric value matching the documented
// Application Key shape (SAP-samples/ariba-extensibility-samples). High
// entropy so it clears the 3.5-bit floor.
const dummy = "uEnCwXMo7YYmQE7el7iqqciAqT7Og0Ik"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.SAPAriba {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("ARIBA_API_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected pins the FP shape now culled: a 32-char
// run with key-grade length and the keyword present, but low information
// content (repetitive), must no longer match.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("ariba_api_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low entropy culled), got %d", len(res))
	}
}

// TestFromData_WrongLengthRejected pins the documented exact-32 length: a
// 40-char high-entropy run near the keyword must not match.
func TestFromData_WrongLengthRejected(t *testing.T) {
	body := []byte("ariba_api_key=uEnCwXMo7YYmQE7el7iqqciAqT7Og0IkXYZ8mnop")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (length != 32 culled), got %d", len(res))
	}
}

// TestFromData_BareKeywordProseRejected pins the radius/arm-regex tightening:
// a high-entropy 32-char token whose only nearby "ariba" is bare prose (no
// assignment anchor) must no longer match.
func TestFromData_BareKeywordProseRejected(t *testing.T) {
	body := []byte("the ariba platform is great. unrelated=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare prose keyword, no arm match), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("apiKey") != dummy {
			t.Errorf("missing apiKey header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil || !v {
		t.Fatalf("err=%v v=%v", err, v)
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
	v, _ := Scanner{}.Verify(context.Background(), dummy)
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
	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_NoApiBase(t *testing.T) {
	old := apiBase
	apiBase = ""
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil || v {
		t.Fatalf("expected unverified no-error, got v=%v err=%v", v, err)
	}
}
