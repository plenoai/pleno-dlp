//go:build detector_unit

package elasticcloud

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyID = "VuaCfGcBCdbkQm-e5aOx"
const dummySecret = "ui2lp2axTNmsyakw9tvNnw"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.ElasticCloud {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# elasticsearch\nES_API_KEY=" + dummyID + ":" + dummySecret)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("rawv2 mismatch: %q", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummyID+":"+dummySecret))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("elastic=" + dummyID + ":" + dummySecret + "\nelastic=" + dummyID + ":" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

// TestVerify_NoApiBase: with no apiBase override the verifier must no-op
// (class a per repo policy) without making any network call.
func TestVerify_NoApiBase(t *testing.T) {
	apiBase = ""
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected unverified without apiBase")
	}
}

func TestVerify_AcceptReject(t *testing.T) {
	wantAuth := "ApiKey " + base64.StdEncoding.EncodeToString([]byte(dummyID+":"+dummySecret))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_security/_authenticate" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != wantAuth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified for accepted credential")
	}

	v, err = Scanner{}.Verify(context.Background(), dummyID+":wrongsecretwrongsecretwrong")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected unverified for rejected credential")
	}
}

// TestVerify_Transient: 500 and 429 must surface a verification error rather
// than asserting (in)validity, so the engine marks the finding "verify failed".
func TestVerify_Transient(t *testing.T) {
	for _, code := range []int{http.StatusInternalServerError, http.StatusTooManyRequests} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		old := apiBase
		apiBase = srv.URL
		v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
		apiBase = old
		srv.Close()
		if err == nil {
			t.Fatalf("code %d: expected transient error, got nil", code)
		}
		if v {
			t.Fatalf("code %d: expected unverified", code)
		}
	}
}

// TestImplementsVerifier guards the class-a contract: the detector must
// satisfy detectors.Verifier so verifycoverage keeps it out of the doc.
func TestImplementsVerifier(t *testing.T) {
	if _, ok := interface{}(Scanner{}).(detectors.Verifier); !ok {
		t.Fatal("Scanner must implement detectors.Verifier")
	}
}
