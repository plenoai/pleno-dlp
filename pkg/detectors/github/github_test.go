package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyClassic = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"                                                    // 36 chars body
const dummyFine = "github_pat_" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_abcdefghijklmnopqrs" // 82 chars body

func TestFromData_Positive(t *testing.T) {
	body := "leak: " + dummyClassic + " and another " + dummyFine
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 results, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("no token here, ghp shorter"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "token ") {
			t.Errorf("missing token auth header: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyClassic)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyClassic)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 401")
	}
}

const (
	testClientID     = "Iv1.test_oauth_client_id"
	testClientSecret = "test_oauth_client_secret_value"
)

// revokeServer returns an httptest server that asserts the request shape
// (path, method, basic auth, JSON body) matches the documented contract
// and serves the requested status. Returns the captured request body.
func revokeServer(t *testing.T, status int) (*httptest.Server, *string) {
	t.Helper()
	captured := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("revoke: expected DELETE, got %s", r.Method)
		}
		wantPath := "/applications/" + testClientID + "/token"
		if r.URL.Path != wantPath {
			t.Errorf("revoke: path = %q, want %q", r.URL.Path, wantPath)
		}
		// Basic auth header MUST be base64(client_id:client_secret).
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			t.Errorf("revoke: missing Basic auth header (%q)", auth)
		} else {
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
			if err != nil {
				t.Errorf("revoke: bad base64 in Basic auth: %v", err)
			} else if got, want := string(decoded), testClientID+":"+testClientSecret; got != want {
				t.Errorf("revoke: basic-auth payload = %q, want %q", got, want)
			}
		}
		body, _ := io.ReadAll(r.Body)
		captured = string(body)
		var parsed struct {
			AccessToken string `json:"access_token"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Errorf("revoke: body is not valid JSON: %v (raw=%q)", err, string(body))
		} else if parsed.AccessToken == "" {
			t.Errorf("revoke: body missing access_token field (raw=%q)", string(body))
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, &captured
}

func withRevokeServer(t *testing.T, status int) (*httptest.Server, *string) {
	srv, captured := revokeServer(t, status)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	SetRevokeCredentials(testClientID, testClientSecret)
	t.Cleanup(func() { SetRevokeCredentials("", "") })
	return srv, captured
}

func TestRevoke_Success(t *testing.T) {
	_, captured := withRevokeServer(t, http.StatusNoContent)

	res, err := Scanner{}.Revoke(context.Background(), dummyClassic)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatal("expected Revoked=true on 204")
	}
	if res.ProviderID != testClientID {
		t.Errorf("ProviderID = %q, want %q", res.ProviderID, testClientID)
	}
	if res.RevokedAt.IsZero() {
		t.Error("RevokedAt unset on success")
	}
	if !strings.Contains(*captured, dummyClassic) {
		t.Errorf("body did not echo token (got %q)", *captured)
	}
}

func TestRevoke_Idempotent_404(t *testing.T) {
	_, _ = withRevokeServer(t, http.StatusNotFound)

	res, err := Scanner{}.Revoke(context.Background(), dummyClassic)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatal("expected Revoked=true on 404 (idempotency)")
	}
	if res.Err == nil {
		t.Fatal("expected non-nil Err diagnostic on 404")
	}
}

func TestRevoke_NotOwnedByApp_422(t *testing.T) {
	_, _ = withRevokeServer(t, http.StatusUnprocessableEntity)

	res, err := Scanner{}.Revoke(context.Background(), dummyClassic)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if res.Revoked {
		t.Fatal("expected Revoked=false on 422")
	}
	if res.Err == nil {
		t.Fatal("expected non-nil Err diagnostic on 422")
	}
}

func TestRevoke_BadCreds_401(t *testing.T) {
	_, _ = withRevokeServer(t, http.StatusUnauthorized)

	_, err := Scanner{}.Revoke(context.Background(), dummyClassic)
	if err == nil {
		t.Fatal("expected hard error on 401")
	}
}

func TestRevoke_MissingCreds(t *testing.T) {
	// Make sure no leftover from a prior test taints this one.
	SetRevokeCredentials("", "")
	t.Setenv(EnvClientID, "")
	t.Setenv(EnvClientSecret, "")

	_, err := Scanner{}.Revoke(context.Background(), dummyClassic)
	if err == nil {
		t.Fatal("expected error when OAuth app creds are unset")
	}
	// The error must name the env vars so operators know how to fix it.
	if !strings.Contains(err.Error(), EnvClientID) || !strings.Contains(err.Error(), EnvClientSecret) {
		t.Errorf("error message should reference %s and %s, got %v", EnvClientID, EnvClientSecret, err)
	}
}

func TestRevoke_EmptySecret(t *testing.T) {
	SetRevokeCredentials(testClientID, testClientSecret)
	t.Cleanup(func() { SetRevokeCredentials("", "") })
	_, err := Scanner{}.Revoke(context.Background(), "")
	if err == nil {
		t.Fatal("expected error on empty secret")
	}
}

func TestRevoke_EnvFallback(t *testing.T) {
	t.Setenv(EnvClientID, testClientID)
	t.Setenv(EnvClientSecret, testClientSecret)
	srv, _ := revokeServer(t, http.StatusNoContent)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	// Make sure programmatic creds are empty so env-fallback fires.
	SetRevokeCredentials("", "")

	res, err := Scanner{}.Revoke(context.Background(), dummyClassic)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatal("expected env-fallback Revoke to succeed on 204")
	}
}

func TestRevoke_InterfaceSatisfied(t *testing.T) {
	// The compile-time assertions in github.go already cover this; the
	// runtime check guards against a future change that drops the
	// interface implementation without touching the assertion (e.g.
	// removing the var block).
	var _ detectors.Revoker = Scanner{}
}
