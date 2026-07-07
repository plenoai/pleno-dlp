//go:build detector_unit

package activecampaign

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdef0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcd"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.ActiveCampaign {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# activecampaign\nAC_API_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("activecampaign_api_key=" + dummy + "\nactivecampaign_api_key=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

// TestFromData_BareKeywordNoArm asserts the FP shape now rejected: a generic
// high-entropy 60-80 char run sitting near a bare "activecampaign" mention but
// with no assignment-style `activecampaign…(token|key|secret)` anchor must not
// match. Before the arm regex, the radius-256 bare-keyword Contains gate
// matched this.
func TestFromData_BareKeywordNoArm(t *testing.T) {
	// High-entropy token (not the hex dummy) near only a bare keyword.
	highEntropy := "Zk9pQ3rT7wXa2bN8mLcV5dF1gH4jKsR6uYeW0iO3pAqZxCvBnMdFgHjKlPoIuYt"
	body := []byte("see https://acme.api-us1.com docs about activecampaign integrations: " + highEntropy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for bare-keyword-no-arm FP shape, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected asserts a 60-80 char run that clears the
// alnum regex and is armed by an assignment anchor but lacks key-grade
// randomness (repeated characters) is dropped by the entropy floor.
func TestFromData_LowEntropyRejected(t *testing.T) {
	lowEntropy := strings.Repeat("ab", 34) // 68 chars, entropy ~1.0 bits/char
	body := []byte("ac_api_key=" + lowEntropy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy run, got %d", len(res))
	}
}

func TestFromData_TooShort(t *testing.T) {
	short := strings.Repeat("a", 40)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("activecampaign "+short))
	if len(res) != 0 {
		t.Fatalf("expected 0 for too-short, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	if got := redact(dummy); !strings.HasSuffix(got, "...") {
		t.Fatalf("redact suffix mismatch: %s", got)
	}
}

// withServer spins up an httptest.Server that asserts the Api-Token header and
// path, returns the given status, and overrides apiBase for the call.
func withServer(t *testing.T, status int) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/3/users/me" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Api-Token") != dummy {
			t.Errorf("missing/incorrect Api-Token header: %q", r.Header.Get("Api-Token"))
		}
		w.WriteHeader(status)
	}))
	prev := apiBase
	apiBase = srv.URL
	return func() {
		apiBase = prev
		srv.Close()
	}
}

func TestVerify_NoOpWithoutAPIBase(t *testing.T) {
	prev := apiBase
	apiBase = ""
	defer func() { apiBase = prev }()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err != nil {
		t.Fatalf("expected no-op (false,nil), got (%v,%v)", v, err)
	}
}

func TestVerify_Accept200(t *testing.T) {
	defer withServer(t, http.StatusOK)()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if !v || err != nil {
		t.Fatalf("expected verified=true,nil on 200, got (%v,%v)", v, err)
	}
}

func TestVerify_Reject401(t *testing.T) {
	defer withServer(t, http.StatusUnauthorized)()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err != nil {
		t.Fatalf("expected verified=false,nil on 401, got (%v,%v)", v, err)
	}
}

func TestVerify_Reject403(t *testing.T) {
	defer withServer(t, http.StatusForbidden)()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err != nil {
		t.Fatalf("expected verified=false,nil on 403, got (%v,%v)", v, err)
	}
}

func TestVerify_Transient500(t *testing.T) {
	defer withServer(t, http.StatusInternalServerError)()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err == nil {
		t.Fatalf("expected verified=false,err on 500, got (%v,%v)", v, err)
	}
}

func TestVerify_Transient429(t *testing.T) {
	defer withServer(t, http.StatusTooManyRequests)()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err == nil {
		t.Fatalf("expected verified=false,err on 429, got (%v,%v)", v, err)
	}
}

func TestFromData_VerifyWired(t *testing.T) {
	defer withServer(t, http.StatusOK)()
	body := []byte("# activecampaign\nAC_API_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), true, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if !res[0].Verified || res[0].VerificationErr != nil {
		t.Fatalf("expected verified result, got verified=%v err=%v", res[0].Verified, res[0].VerificationErr)
	}
}
