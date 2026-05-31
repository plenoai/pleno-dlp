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
	body := []byte("activecampaign " + dummy + "\nactivecampaign " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
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
