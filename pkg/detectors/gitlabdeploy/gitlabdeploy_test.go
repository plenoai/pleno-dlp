//go:build detector_unit

package gitlabdeploy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyDeploy = "gldt-AbCdEfGhIjKlMnOpQrSt"
const dummyAgent = "glagent-AbCdEfGhIjKlMnOpQrSt"

func TestFromData_Deploy(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("CI_DEPLOY_TOKEN="+dummyDeploy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyDeploy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Agent(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("KAS_TOKEN="+dummyAgent))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_Negative_PAT(t *testing.T) {
	// glpat- is the user PAT shape, owned by the gitlab detector. Do not
	// fire here.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X=glpat-AbCdEfGhIjKlMnOpQrSt"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyDeploy)
	if r == dummyDeploy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "gldt-AbCdE") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummyDeploy {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyDeploy)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyDeploy)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyDeploy)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
