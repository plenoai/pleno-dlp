//go:build detector_unit

package argocd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhcmdvIn0.AbCdEf0123456789AbCdEf01"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.ArgoCD {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("ARGOCD_TOKEN=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoContext(t *testing.T) {
	body := []byte("# generic jwt\nX=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without argocd context, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("argocd_token=" + dummy + "\nargocd_token=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
}

// withServer points apiBase at a test server returning the given status and
// restores apiBase afterwards.
func withServer(t *testing.T, status int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/account" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+dummy {
			t.Errorf("expected bearer auth, got %q", got)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
}

func TestVerify_NoApiBase_NoOp(t *testing.T) {
	old := apiBase
	apiBase = ""
	t.Cleanup(func() { apiBase = old })
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err != nil {
		t.Fatalf("expected no-op (false,nil), got (%v,%v)", v, err)
	}
}

func TestVerify_Accept200(t *testing.T) {
	withServer(t, http.StatusOK)
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if !v || err != nil {
		t.Fatalf("expected verified true, got (%v,%v)", v, err)
	}
}

func TestVerify_Accept403(t *testing.T) {
	withServer(t, http.StatusForbidden)
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if !v || err != nil {
		t.Fatalf("403 (authenticated, RBAC-denied) should still verify, got (%v,%v)", v, err)
	}
}

func TestVerify_Reject401(t *testing.T) {
	withServer(t, http.StatusUnauthorized)
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err != nil {
		t.Fatalf("401 should be clean rejection (false,nil), got (%v,%v)", v, err)
	}
}

func TestVerify_Transient429(t *testing.T) {
	withServer(t, http.StatusTooManyRequests)
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err == nil {
		t.Fatalf("429 should be transient (false,err), got (%v,%v)", v, err)
	}
}

func TestVerify_Transient500(t *testing.T) {
	withServer(t, http.StatusInternalServerError)
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err == nil {
		t.Fatalf("500 should be transient (false,err), got (%v,%v)", v, err)
	}
}

func TestFromData_VerifyWired(t *testing.T) {
	withServer(t, http.StatusOK)
	body := []byte("ARGOCD_TOKEN=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), true, body)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if !res[0].Verified || res[0].VerificationErr != nil {
		t.Fatalf("expected verified result, got verified=%v err=%v", res[0].Verified, res[0].VerificationErr)
	}
}
