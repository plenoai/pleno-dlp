package hasura

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a 64-char high-entropy alphanumeric matching the documented Hasura
// admin-secret shape (`[a-zA-Z0-9]{64}`). Not a real secret.
const dummy = "aZ7kQ2mP9xR4wL8nB6vT3yC1dH5gF0jKsE2uW4iO9pXqM7lN3bV6cZ8aS1dG4hJ0"

// lowEntropyRun is a 64-char alphanumeric run with low Shannon entropy — the
// false-positive shape now rejected by the entropy floor even when armed.
const lowEntropyRun = "abababababababababababababababababababababababababababababababab"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Hasura {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("HASURA_ADMIN_SECRET=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected pins the new entropy floor: a 64-char
// alphanumeric run that arms the keyword gate but is low-entropy (the classic
// false-positive shape) must no longer be surfaced.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("HASURA_ADMIN_SECRET=" + lowEntropyRun)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy run rejected), got %d", len(res))
	}
}

// TestFromData_BareKeywordNoAssignment pins the arm-regex tightening: a bare
// "hasura" mention near a high-entropy 64-char token, without an
// admin-secret-style assignment, must not arm.
func TestFromData_BareKeywordNoAssignment(t *testing.T) {
	body := []byte("see the hasura graphql tutorial " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword, no assignment), got %d", len(res))
	}
}

func TestVerify_Disabled_Default(t *testing.T) {
	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false default")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-hasura-admin-secret") != dummy {
			t.Errorf("header mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil || !v {
		t.Fatalf("err=%v v=%v", err, v)
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
}
