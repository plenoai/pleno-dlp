package bamboohr

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a spec-correct 40-hex-char value (160-bit secret in hexadecimal
// form, per https://documentation.bamboohr.com/docs/getting-started). Entropy
// ~3.95, above the 3.0 floor.
const dummy = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.BambooHR {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("BAMBOOHR_API_KEY=" + dummy)
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

// TestFromData_RejectsNonHexHighEntropy guards the charset tightening: a
// 40-char base62 high-entropy string (entropy ~5.0, well above the floor) sat
// next to the keyword used to match the old [A-Za-z0-9]{40,64} regex. With the
// hex-only charset it must no longer be reported.
func TestFromData_RejectsNonHexHighEntropy(t *testing.T) {
	body := []byte("BAMBOOHR_API_KEY=Xq7Zk9pLmW3vRtYuIoPaSdFgHjKlZxCvBnMqWeRt")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (non-hex shape), got %d", len(res))
	}
}

// TestFromData_RejectsBareKeywordProximity guards the arm-regex gate: a real
// 40-hex key merely co-located with the bare word "bamboohr" (e.g. a prose
// mention) without an assignment-style anchor must no longer be promoted.
func TestFromData_RejectsBareKeywordProximity(t *testing.T) {
	body := []byte("see the bamboohr integration notes; commit " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword, no anchor), got %d", len(res))
	}
}

// TestFromData_RejectsLowEntropyHex guards the entropy floor: a degenerate
// 40-hex run (repeated digit) clears the regex but is not a real key.
func TestFromData_RejectsLowEntropyHex(t *testing.T) {
	body := []byte("BAMBOOHR_API_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy hex), got %d", len(res))
	}
}

func TestVerify_Disabled_Default(t *testing.T) {
	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false when apiBase empty")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != dummy || p != "x" {
			t.Errorf("basic-auth mismatch")
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
