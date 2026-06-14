//go:build detector_unit

package vonage

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyKey    = "abcd1234"
	dummySecret = "AbCdEf0123456789"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Vonage {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# vonage\nVONAGE_API_KEY=" + dummyKey + "\nVONAGE_API_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].RawV2) != dummyKey+":"+dummySecret {
		t.Fatalf("expected RawV2 packed key:secret, got %q", res[0].RawV2)
	}
}

// TestFromData_RejectsHexDigestSecret is the FP-hardening regression: a generic
// high-entropy 16-char run that lacks the documented upper+lower+digit
// composition (here a lowercase hex digest) must no longer be admitted as a
// secret even though it sits next to a vonage_api_secret reference and clears
// the bare alnum regex.
func TestFromData_RejectsHexDigestSecret(t *testing.T) {
	body := []byte("# vonage\nVONAGE_API_KEY=" + dummyKey + "\nVONAGE_API_SECRET=a1b2c3d4e5f6a7b8")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (hex digest fails composition), got %d", len(res))
	}
}

// TestFromData_RejectsLowEntropySecret: a run that satisfies the upper+lower+digit
// composition but is low-entropy (repeated triplet) must be culled by the
// entropy floor.
func TestFromData_RejectsLowEntropySecret(t *testing.T) {
	body := []byte("# vonage\nVONAGE_API_KEY=" + dummyKey + "\nVONAGE_API_SECRET=Aa1Aa1Aa1Aa1")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low entropy), got %d", len(res))
	}
}

// TestFromData_RadiusTightened: a bare "vonage" mention more than 64 bytes from
// the credential no longer arms the detector (radius shrunk 256 -> 64, and the
// gate now requires an assignment-style reference, not a bare substring).
func TestFromData_RadiusTightened(t *testing.T) {
	filler := make([]byte, 120)
	for i := range filler {
		filler[i] = '.'
	}
	body := []byte("vonage stuff" + string(filler) + "KEY=" + dummyKey + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (keyword beyond radius 64 / not an arm reference), got %d", len(res))
	}
}

func TestImplementsVerifier(t *testing.T) {
	if _, ok := interface{}(Scanner{}).(detectors.Verifier); !ok {
		t.Fatal("Scanner must satisfy detectors.Verifier (class a)")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("KEY=" + dummyKey + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	expected := base64.StdEncoding.EncodeToString([]byte(dummyKey + ":" + dummySecret))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Basic "+expected {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
	if err != nil || !v {
		t.Fatalf("verified expected true: err=%v v=%v", err, v)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
	if v || err != nil {
		t.Fatalf("expected verified=false,nil err on 403: v=%v err=%v", v, err)
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

	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false on 500")
	}
	if err == nil {
		t.Fatal("expected transient error on 500")
	}
}

func TestVerify_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false on 429")
	}
	if err == nil {
		t.Fatal("expected transient error on 429")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false")
	}
}
