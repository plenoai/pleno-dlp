package gitlab

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	testTokenID = 42
)

// revokeMux returns an httptest server that asserts request shape against
// the documented 2-step contract. selfStatus / revokeStatus pick the
// response code each leg returns. The Authorization header MUST be
// `Bearer <token>` on both legs.
func revokeMux(t *testing.T, selfStatus, revokeStatus int) *httptest.Server {
	t.Helper()
	wantAuth := "Bearer " + dummyToken
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/personal_access_tokens/self", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("self: expected GET, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Errorf("self: Authorization = %q, want %q", got, wantAuth)
		}
		if selfStatus == http.StatusOK {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"id":%d,"name":"dummy","revoked":false}`, testTokenID)
			return
		}
		w.WriteHeader(selfStatus)
	})
	mux.HandleFunc(fmt.Sprintf("/api/v4/personal_access_tokens/%d/revoke", testTokenID), func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("revoke: expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Errorf("revoke: Authorization = %q, want %q", got, wantAuth)
		}
		w.WriteHeader(revokeStatus)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func withAPIBase(t *testing.T, url string) {
	t.Helper()
	old := apiBase
	apiBase = url
	t.Cleanup(func() { apiBase = old })
}

func TestRevoke_Success(t *testing.T) {
	srv := revokeMux(t, http.StatusOK, http.StatusNoContent)
	withAPIBase(t, srv.URL)

	res, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatal("expected Revoked=true on 204")
	}
	if res.ProviderID != fmt.Sprintf("%d", testTokenID) {
		t.Errorf("ProviderID = %q, want %q", res.ProviderID, fmt.Sprintf("%d", testTokenID))
	}
	if res.RevokedAt.IsZero() {
		t.Error("RevokedAt unset on success")
	}
	if res.Err != nil {
		t.Errorf("expected nil Err on clean 204, got %v", res.Err)
	}
}

func TestRevoke_SelfUnauthorized_Idempotent(t *testing.T) {
	// Self returns 401 — token is already revoked or invalid. Revoke
	// MUST report success (idempotent) so retry loops don't escalate.
	srv := revokeMux(t, http.StatusUnauthorized, http.StatusNoContent)
	withAPIBase(t, srv.URL)

	res, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatal("expected Revoked=true on self 401 (idempotency)")
	}
	if res.Err == nil {
		t.Fatal("expected non-nil Err diagnostic on self 401")
	}
}

func TestRevoke_SelfForbidden_Idempotent(t *testing.T) {
	srv := revokeMux(t, http.StatusForbidden, http.StatusNoContent)
	withAPIBase(t, srv.URL)

	res, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatal("expected Revoked=true on self 403 (idempotency)")
	}
	if res.Err == nil {
		t.Fatal("expected non-nil Err diagnostic on self 403")
	}
}

func TestRevoke_RevokeStep_404_Idempotent(t *testing.T) {
	srv := revokeMux(t, http.StatusOK, http.StatusNotFound)
	withAPIBase(t, srv.URL)

	res, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatal("expected Revoked=true on revoke 404 (idempotency)")
	}
	if res.Err == nil {
		t.Fatal("expected non-nil Err diagnostic on revoke 404")
	}
}

func TestRevoke_RevokeStep_401_Idempotent(t *testing.T) {
	srv := revokeMux(t, http.StatusOK, http.StatusUnauthorized)
	withAPIBase(t, srv.URL)

	res, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatal("expected Revoked=true on revoke 401 (idempotency)")
	}
	if res.Err == nil {
		t.Fatal("expected non-nil Err diagnostic on revoke 401")
	}
}

func TestRevoke_RevokeStep_429_HardError(t *testing.T) {
	srv := revokeMux(t, http.StatusOK, http.StatusTooManyRequests)
	withAPIBase(t, srv.URL)

	_, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err == nil {
		t.Fatal("expected hard error on revoke 429")
	}
}

func TestRevoke_RevokeStep_UnexpectedStatus_HardError(t *testing.T) {
	srv := revokeMux(t, http.StatusOK, http.StatusInternalServerError)
	withAPIBase(t, srv.URL)

	_, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err == nil {
		t.Fatal("expected hard error on revoke 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should reference HTTP status, got %v", err)
	}
}

func TestRevoke_NetworkError_HardError(t *testing.T) {
	// Point at a closed server URL so http.Do returns a connection error.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	withAPIBase(t, url)

	_, err := Scanner{}.Revoke(context.Background(), dummyToken)
	if err == nil {
		t.Fatal("expected network error to surface as hard error")
	}
}

func TestRevoke_EmptySecret_HardError(t *testing.T) {
	_, err := Scanner{}.Revoke(context.Background(), "")
	if err == nil {
		t.Fatal("expected error on empty secret")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("error should mention empty secret, got %v", err)
	}
}

func TestRevoke_InterfaceSatisfied(t *testing.T) {
	// Compile-time assertion lives in gitlab.go; this runtime check
	// guards against a future change that drops the interface
	// implementation without touching the assertion block.
	var _ detectors.Revoker = Scanner{}
}
