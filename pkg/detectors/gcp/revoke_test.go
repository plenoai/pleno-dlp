//go:build detector_unit

package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func revokeKeyJSON(t *testing.T) string {
	t.Helper()
	b, _ := json.Marshal(serviceAccount{
		Type:        "service_account",
		ClientEmail: "sa@example-proj.iam.gserviceaccount.com",
		PrivateKey:  genKey(t),
		ProjectID:   "example-proj",
		KeyID:       "abc123",
	})
	return string(b)
}

func setupRevoke(t *testing.T, tokenCode, deleteCode int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			w.WriteHeader(tokenCode)
			_, _ = w.Write([]byte(`{"access_token":"ya29.test"}`))
		case "/v1/projects/example-proj/serviceAccounts/sa@example-proj.iam.gserviceaccount.com/keys/abc123":
			if r.Method != http.MethodDelete || r.Header.Get("Authorization") != "Bearer ya29.test" {
				t.Errorf("got %s auth=%q", r.Method, r.Header.Get("Authorization"))
			}
			w.WriteHeader(deleteCode)
			_, _ = w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	oldTok, oldIAM := tokenURL, iamBase
	tokenURL, iamBase = srv.URL+"/token", srv.URL
	t.Cleanup(func() { tokenURL, iamBase = oldTok, oldIAM })
}

func TestRevoke_DeletesKey(t *testing.T) {
	setupRevoke(t, 200, 200)
	res, err := Scanner{}.Revoke(context.Background(), revokeKeyJSON(t))
	if err != nil || !res.Revoked || res.Err != nil || res.ProviderID != "sa@example-proj.iam.gserviceaccount.com/abc123" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestRevoke_Outcomes(t *testing.T) {
	key := revokeKeyJSON(t)
	setupRevoke(t, 400, 200)
	if res, err := (Scanner{}).Revoke(context.Background(), key); err != nil || !res.Revoked || res.Err == nil {
		t.Errorf("rejected grant is idempotent: %+v %v", res, err)
	}
	setupRevoke(t, 200, 404)
	if res, err := (Scanner{}).Revoke(context.Background(), key); err != nil || !res.Revoked || res.Err == nil {
		t.Errorf("404 is idempotent: %+v %v", res, err)
	}
	for _, code := range []int{403, 500} {
		setupRevoke(t, 200, code)
		if _, err := (Scanner{}).Revoke(context.Background(), key); err == nil {
			t.Errorf("%d must error", code)
		}
	}
}

func TestRevoke_RejectsNonJSON(t *testing.T) {
	// Scan-path Raw is client_email only; it must not be mistaken for a key.
	if _, err := (Scanner{}).Revoke(context.Background(), "sa@example-proj.iam.gserviceaccount.com"); err == nil {
		t.Fatal("email-only secret must error")
	}
	if _, err := (Scanner{}).Revoke(context.Background(), `{"client_email":"a@b"}`); err == nil {
		t.Fatal("incomplete JSON must error")
	}
}
