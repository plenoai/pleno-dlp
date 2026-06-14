//go:build detector_unit

package newrelic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	// NRRA- + 42 chars [a-zA-Z0-9-]
	dummyLicense = "NRRA-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-abcde"
	// NRAK- + 27 chars [A-Z0-9]
	dummyIngest = "NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ0"
	// NRII- + 32 chars [A-Za-z0-9-]
	dummyInsert = "NRII-aBcDeFgHiJ0123456789-aBcDeFgHi01"
)

func TestFromData_License(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("X="+dummyLicense))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].ExtraData["kind"] != "license" {
		t.Fatalf("kind mismatch: %q", res[0].ExtraData["kind"])
	}
}

func TestFromData_AllKinds(t *testing.T) {
	body := []byte("a=" + dummyLicense + "\nb=" + dummyIngest + "\nc=" + dummyInsert)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 3 {
		t.Fatalf("expected 3, got %d", len(res))
	}
	kinds := map[string]bool{}
	for _, r := range res {
		kinds[r.ExtraData["kind"]] = true
	}
	for _, want := range []string{"license", "ingest", "insert"} {
		if !kinds[want] {
			t.Fatalf("missing kind %q", want)
		}
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("NRRA-short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyLicense)
	if !strings.HasPrefix(r, "NRRA-") {
		t.Fatalf("missing prefix: %q", r)
	}
	if r == dummyLicense {
		t.Fatal("redact didn't redact")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != dummyLicense {
			t.Errorf("api-key mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyLicense)
	if err != nil {
		t.Fatalf("err: %v", err)
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
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyLicense)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}
