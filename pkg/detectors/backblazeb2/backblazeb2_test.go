//go:build detector_unit

package backblazeb2

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyID  = "K003abcdef0123456789ghijk"
	dummyKey = "K003ABCDEF0123456789ghijklMNOPQRstuvwxyz"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.BackblazeB2 {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# b2_application_key\nB2_KEY_ID=" + dummyID + "\nB2_APP_KEY=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].Raw) != dummyID {
		t.Fatalf("Raw mismatch: %q", res[0].Raw)
	}
	wantV2 := dummyID + ":" + dummyKey
	if string(res[0].RawV2) != wantV2 {
		t.Fatalf("RawV2 mismatch: got %q want %q", res[0].RawV2, wantV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("X=" + dummyID + "\nY=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_OnlyID(t *testing.T) {
	body := []byte("b2_app id only " + dummyID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without paired key, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("b2_ " + dummyID + "\nb2_ " + dummyKey + "\nb2_ " + dummyID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

// verifyServer returns an httptest server that asserts the request carries
// the expected Basic-auth credential and replies with the given status.
func verifyServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	wantCred := "Basic " + base64.StdEncoding.EncodeToString([]byte(dummyID+":"+dummyKey))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/b2_authorize_account") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != wantCred {
			t.Errorf("auth header mismatch: got %q want %q", got, wantCred)
		}
		w.WriteHeader(status)
	}))
}

func withAPIBase(t *testing.T, url string) {
	t.Helper()
	old := apiBase
	apiBase = url
	t.Cleanup(func() { apiBase = old })
}

func TestVerify_OK(t *testing.T) {
	srv := verifyServer(t, http.StatusOK)
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := verifyServer(t, http.StatusUnauthorized)
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 401")
	}
}

func TestVerify_Forbidden(t *testing.T) {
	srv := verifyServer(t, http.StatusForbidden)
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 403")
	}
}

func TestVerify_RateLimitedTransient(t *testing.T) {
	srv := verifyServer(t, http.StatusTooManyRequests)
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
	if err == nil {
		t.Fatal("expected transient error on 429")
	}
	if v {
		t.Fatal("expected verified=false on 429")
	}
}

func TestVerify_ServerErrorTransient(t *testing.T) {
	srv := verifyServer(t, http.StatusInternalServerError)
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
	if err == nil {
		t.Fatal("expected transient error on 500")
	}
	if v {
		t.Fatal("expected verified=false on 500")
	}
}

func TestVerify_BadPair(t *testing.T) {
	v, err := Scanner{}.Verify(context.Background(), "no-colon-here")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false for unsplittable secret")
	}
}

func TestFromData_VerifySetsResult(t *testing.T) {
	srv := verifyServer(t, http.StatusOK)
	defer srv.Close()
	withAPIBase(t, srv.URL)

	body := []byte("# b2_application_key\nB2_KEY_ID=" + dummyID + "\nB2_APP_KEY=" + dummyKey)
	res, err := Scanner{}.FromData(context.Background(), true, body)
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatalf("expected Verified=true, err=%v", res[0].VerificationErr)
	}
}
