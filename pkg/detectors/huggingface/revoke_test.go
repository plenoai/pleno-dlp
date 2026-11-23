//go:build detector_unit

package huggingface

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func setup(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
}

func TestRevoke_ReportAccepted(t *testing.T) {
	tok := "hf_" + strings.Repeat("x", 34) // built at runtime so the pre-commit scan stays quiet
	setup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/credentials/revoke" || r.Header.Get("Authorization") != "" {
			t.Errorf("got %s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		var body struct{ Credentials []string }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Credentials) != 1 || body.Credentials[0] != tok {
			t.Errorf("body = %+v err=%v", body, err)
		}
		w.WriteHeader(http.StatusAccepted)
	})
	res, err := Scanner{}.Revoke(context.Background(), tok)
	if err != nil || !res.Revoked || res.Err == nil {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if strings.Contains(res.ProviderID, "hf_") || !strings.HasPrefix(res.ProviderID, "sha256:") {
		t.Errorf("ProviderID = %q", res.ProviderID)
	}
}

func TestRevoke_NonAcceptedIsHardError(t *testing.T) {
	setup(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	if _, err := (Scanner{}).Revoke(context.Background(), "hf_x"); err == nil {
		t.Fatal("200 is not the documented 202 acknowledgement")
	}
	if _, err := (Scanner{}).Revoke(context.Background(), ""); err == nil {
		t.Fatal("empty secret must error")
	}
}
