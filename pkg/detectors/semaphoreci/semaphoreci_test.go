//go:build detector_unit

package semaphoreci

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyToken = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.SemaphoreCI {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("semaphore_token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

// Realistic assignment shapes the arm regex must still arm on, so recall on
// genuine config keys is preserved after the radius/arm-regex tightening.
func TestFromData_ArmVariants(t *testing.T) {
	cases := []string{
		"SEMAPHORE_API_TOKEN=" + dummyToken,
		"semaphoreci-key: " + dummyToken,
		"semaphore_secret = " + dummyToken,
	}
	for _, body := range cases {
		res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
		if len(res) == 0 {
			t.Fatalf("expected >=1 for %q, got 0", body)
		}
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without semaphore keyword, got %d", len(res))
	}
}

// Regression for the false-positive shape the hardening now rejects: a generic
// high-entropy 40-char run sitting next to a bare "semaphore" mention (e.g. the
// Go sync.Semaphore type or a semaphore CLI library reference) that is NOT a
// token assignment. Pre-hardening the radius-256 bare-Contains gate matched
// this; the arm regex must now reject it.
func TestFromData_RejectsBareKeywordHighEntropy(t *testing.T) {
	// dummyToken is high-entropy (Shannon ~5.6), so this isolates the arm-regex
	// gate, not the entropy floor.
	body := []byte("acquired the semaphore before writing " + dummyToken + " to the cache key")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword high-entropy FP shape, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("semaphore_token=" + dummyToken + "\nsemaphoreci_key=" + dummyToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token "+dummyToken {
			t.Errorf("auth mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyToken)
	if err != nil || !v {
		t.Fatalf("expected verified=true: err=%v v=%v", err, v)
	}
}

func TestVerify_NoHost(t *testing.T) {
	old := apiBase
	apiBase = ""
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummyToken)
	if v {
		t.Fatal("expected verified=false when apiBase empty")
	}
}
