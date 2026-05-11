package sift

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyID = "abcdef0123456789ABCDEF"
const dummyKey = "1234567890abcdef1234567890ABCDEF"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Sift {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("SIFT_ACCOUNT_ID=" + dummyID + "\nSIFT_API_KEY=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_FoundSiftscience(t *testing.T) {
	body := []byte("# siftscience credentials\naccount=" + dummyID + "\nkey=" + dummyKey + "\n# end siftscience block")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 for siftscience anchor")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED=" + dummyID + "\nOTHER=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// --- FP regressions -----------------------------------------------

// "sifted" / "sifting" / "shift" prose with two 20+ char alphanumeric
// blobs must not trigger.
func TestFromData_FP_SiftedProse(t *testing.T) {
	body := []byte("// we sifted through " + dummyID + " and found " + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("sifted FP: expected 0, got %d", len(res))
	}
}

func TestFromData_FP_ShiftProse(t *testing.T) {
	body := []byte("// shift commit " + dummyID + " to branch " + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("shift FP: expected 0, got %d", len(res))
	}
}

// Two unrelated 20+ char blobs without any sift anchor.
func TestFromData_FP_TwoUnrelatedBlobs(t *testing.T) {
	body := []byte("key1=" + dummyID + "\nkey2=" + dummyKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("two-unrelated-blobs FP: expected 0, got %d", len(res))
	}
}

// Low-entropy ident/key pairs satisfy [A-Za-z0-9]{20,80} but
// carry no key material — entropy gate rejects.
func TestFromData_FP_LowEntropyZeros(t *testing.T) {
	zero := "00000000000000000000000000000000"
	body := []byte("SIFT_ACCOUNT_ID=" + zero + "\nSIFT_API_KEY=" + zero + "x")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("low-entropy zeros FP: expected 0, got %d", len(res))
	}
}

func TestFromData_FP_LowEntropyRepeated(t *testing.T) {
	rep := "ababababababababababababababab"
	body := []byte("siftscience account=" + rep + "\nkey=" + rep + "xy")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("low-entropy repeated FP: expected 0, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("missing auth header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummyKey)
	if v {
		t.Fatal("expected verified=false")
	}
}
