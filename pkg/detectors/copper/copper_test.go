//go:build detector_unit

package copper

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyEmail = "ops@example.com"
	// 32-char lowercase-hex, matching the documented Copper key shape
	// (upstream trufflehog: \b([a-z0-9]{32})\b). Entropy ~3.9, clears
	// the 3.0 hex floor.
	dummyToken = "9f3a1c7b2e8d4a6f0b5c9e1d7a3f8b2c"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Copper {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("COPPER_USER_EMAIL=" + dummyEmail + " COPPER_API_KEY=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED1=" + dummyEmail + " UNRELATED2=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm exercises the radius/arm tightening: a
// high-entropy 32-char hex blob (a git blob hash, an md5 digest) sitting
// near a bare "copper" mention — but with no copper_(api_)?token/key/secret
// assignment anchor — must NOT arm the detector. Under the old radius-256
// bare-Contains gate this was a false positive.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	body := []byte("# copper plumbing notes\nuser=" + dummyEmail +
		"\nblob_sha=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (no arm anchor), got %d", len(res))
	}
}

// TestFromData_LowEntropyToken confirms the entropy floor rejects a
// structured 32-char hex run even when the arm anchor is present.
func TestFromData_LowEntropyToken(t *testing.T) {
	body := []byte("COPPER_USER_EMAIL=" + dummyEmail +
		" COPPER_API_KEY=00000000000000000000000000000000")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low entropy), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PW-AccessToken") != dummyToken {
			t.Errorf("token mismatch")
		}
		if r.Header.Get("X-PW-UserEmail") != dummyEmail {
			t.Errorf("email mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyEmail+":"+dummyToken)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyEmail+":"+dummyToken)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyEmail+":"+dummyToken)
	if v {
		t.Fatal("expected verified=false")
	}
}
