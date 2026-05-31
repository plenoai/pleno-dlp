package helpscout

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	dummyID     = "abcdef0123456789ABCDEF0123456789"
	dummySecret = "abcdefABCDEF0123456789abcdef0123"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.HelpScout {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("HELPSCOUT_APP_ID=" + dummyID + " HELPSCOUT_APP_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED1=" + dummyID + " UNRELATED2=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected is the FP-hardening regression: structured/
// low-information 32-char runs sitting right next to the helpscout assignment
// keywords used to match under the old bare-keyword radius-256 gate. The
// HasMinEntropy(3.0) floor now rejects them.
func TestFromData_LowEntropyRejected(t *testing.T) {
	const lowA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 32 'a's, entropy 0
	const lowB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	body := []byte("HELPSCOUT_APP_ID=" + lowA + " HELPSCOUT_APP_SECRET=" + lowB)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy runs rejected), got %d", len(res))
	}
}

// TestFromData_KeywordWithoutArm is the radius/arm regression: a bare mention of
// the word "helpscout" far from any credential-shaped assignment no longer arms
// the detector. The old gate fired on any "helpscout" substring within 256
// chars; the arm regex requires an assignment shape within 64 chars.
func TestFromData_KeywordWithoutArm(t *testing.T) {
	body := []byte("we migrated from helpscout last year. CONFIG_A=" + dummyID + " CONFIG_B=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (no arm match near tokens), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s := string(b)
		if !strings.Contains(s, "client_id="+dummyID) || !strings.Contains(s, "client_secret="+dummySecret) {
			t.Errorf("body mismatch: %s", s)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}
