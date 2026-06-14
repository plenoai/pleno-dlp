//go:build detector_unit

package lemlist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyEmail = "user@example.com"
	// 32-char lowercase hex, matching the lemlist API key shape
	// (`[a-f0-9]{32}`). High-variety nibbles so it clears the 3.0 entropy floor.
	dummyToken = "3f9a1c7b2e8d4056af13b9c0d72e6481"
	// lowEntropyHex is a 32-char hex run that clears the regex but is a
	// repeated-nibble placeholder, not a real token — must be rejected.
	lowEntropyHex = "00000000000000000000000000000000"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Lemlist {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("LEMLIST_USER=" + dummyEmail + " LEMLIST_API_KEY=" + dummyToken)
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

func TestFromData_LowEntropyRejected(t *testing.T) {
	// A 32-char hex run near the keyword that is a repeated-nibble placeholder
	// must no longer match now that an entropy floor is in place.
	body := []byte("LEMLIST_USER=" + dummyEmail + " LEMLIST_API_KEY=" + lowEntropyHex)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy placeholder, got %d", len(res))
	}
}

func TestFromData_WeakKeywordRejected(t *testing.T) {
	// A real-shaped token sitting next to a bare "lemlist" mention (e.g. a doc
	// URL) with no assignment arm must not match under the arm-regex gate.
	body := []byte("see https://api.lemlist.com/docs and value " + dummyToken + " for " + dummyEmail)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword context, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, _ := r.BasicAuth()
		if u != dummyEmail || p != dummyToken {
			t.Errorf("auth mismatch")
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
