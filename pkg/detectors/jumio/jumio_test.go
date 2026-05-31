package jumio

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyKey    = "abcdef0123456789ABCDEF0123456789abcdef01"
	dummySecret = "ZYXWVU9876543210zyxwvu9876543210ZYXWVU98"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Jumio {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("JUMIO_API_TOKEN=" + dummyKey + " JUMIO_API_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 paired result, got %d", len(res))
	}
	if string(res[0].RawV2) != dummyKey+":"+dummySecret {
		t.Fatalf("RawV2 mismatch: %s", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED_KEY=" + dummyKey + " UNRELATED_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_KeywordButNoAnchor covers the historical false-positive
// shape: the word "jumio" co-occurs in the chunk (e.g. a doc comment or
// CDN URL) alongside two unrelated high-entropy blobs (asset hashes,
// git SHAs). The old whole-file Contains gate paired them; the windowed
// assignment anchor must reject them.
func TestFromData_KeywordButNoAnchor(t *testing.T) {
	body := []byte("// jumio integration notes\nasset_hash=" + dummyKey + "\nbuild_sha=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (no assignment anchor), got %d", len(res))
	}
}

// TestFromData_AnchorButLowEntropy ensures a properly-anchored but
// low-entropy run (repeated chars padded to length) is rejected by the
// entropy gate rather than paired.
func TestFromData_AnchorButLowEntropy(t *testing.T) {
	lowEnt := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 40 'a's, len in [32,64]
	body := []byte("JUMIO_API_TOKEN=" + lowEnt + " JUMIO_API_SECRET=" + lowEnt)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low entropy), got %d", len(res))
	}
}

// TestFromData_AnchorVariants confirms the anchor regex accepts the
// dash/no-underscore and bare token/secret spellings.
func TestFromData_AnchorVariants(t *testing.T) {
	body := []byte("jumio-token: " + dummyKey + "\njumio_secret = " + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 paired result, got %d", len(res))
	}
	if string(res[0].RawV2) != dummyKey+":"+dummySecret {
		t.Fatalf("RawV2 mismatch: %s", res[0].RawV2)
	}
}

func TestVerify_NoBase(t *testing.T) {
	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
	if err != nil || v {
		t.Fatalf("expected unverified without apiBase")
	}
}

func TestVerify_OK(t *testing.T) {
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(dummyKey+":"+dummySecret))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != want {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyKey+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}
