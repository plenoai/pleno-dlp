//go:build detector_unit

package gcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func genKey(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func sampleJSON(t *testing.T) []byte {
	t.Helper()
	sa := serviceAccount{
		Type:        "service_account",
		ClientEmail: "tester@example-proj.iam.gserviceaccount.com",
		PrivateKey:  genKey(t),
		TokenURI:    "https://oauth2.googleapis.com/token",
		ProjectID:   "example-proj",
	}
	b, err := json.Marshal(sa)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestFromData_Positive(t *testing.T) {
	blob := sampleJSON(t)
	wrapped := []byte("LEAD\n" + string(blob) + "\nTRAIL")
	res, err := Scanner{}.FromData(context.Background(), false, wrapped)
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].ExtraData["project_id"] != "example-proj" {
		t.Fatalf("missing project_id: %+v", res[0].ExtraData)
	}
	if !strings.Contains(string(res[0].RawV2), "service_account") {
		t.Fatalf("RawV2 must contain the JSON blob")
	}
}

func TestFromData_NotAServiceAccount(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(`{"type": "user"}`))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact("tester@example-proj.iam.gserviceaccount.com")
	if strings.Contains(r, "tester@example") {
		t.Fatalf("redact leaked: %q", r)
	}
	if !strings.Contains(r, "iam.gserviceaccount.com") {
		t.Fatalf("redact dropped domain: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
			t.Errorf("bad grant_type: %q", r.PostForm.Get("grant_type"))
		}
		if r.PostForm.Get("assertion") == "" {
			t.Error("assertion missing")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"x","token_type":"Bearer","expires_in":3599}`))
	}))
	defer srv.Close()
	old := tokenURL
	tokenURL = srv.URL
	defer func() { tokenURL = old }()

	v, err := Scanner{}.Verify(context.Background(), string(sampleJSON(t)))
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := tokenURL
	tokenURL = srv.URL
	defer func() { tokenURL = old }()

	v, err := Scanner{}.Verify(context.Background(), string(sampleJSON(t)))
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}
