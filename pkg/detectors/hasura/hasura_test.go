//go:build detector_unit

package hasura

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a 64-char high-entropy alphanumeric matching the Hasura
// admin-secret shape. Not a real secret.
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
// alphanumeric run that arms the keyword gate but is low-entropy must no
// longer be surfaced.
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
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/graphql" {
			t.Errorf("path = %s, want /v1/graphql", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"query_root"}}}}`))
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

func TestVerify_HTTP200GraphQLErrorRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":null,"errors":[{"message":"access denied"}]}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("explicit GraphQL rejection returned error: %v", err)
	}
	if v {
		t.Fatal("HTTP 200 GraphQL error must not verify")
	}
}

func TestVerify_HTTP200MalformedBodyIsIndeterminate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not-json`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("malformed GraphQL response must be indeterminate")
	}
	if v {
		t.Fatal("malformed GraphQL response must not verify")
	}
}

func TestVerify_HTTP200OversizedBodyIsIndeterminate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat(" ", (64<<10)+1) + `{"data":{"__schema":{"queryType":{"name":"query_root"}}}}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("oversized response must be indeterminate")
	}
	if v {
		t.Fatal("oversized response must not verify")
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
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("explicit rejection returned error: %v", err)
	}
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
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("server error must be indeterminate")
	}
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestFromData_ServerErrorProducesIndeterminateVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	results, err := Scanner{}.FromData(
		context.Background(),
		true,
		[]byte("HASURA_ADMIN_SECRET="+dummy),
	)
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}
	if got := results[0].Verdict(); got != detectors.VerdictIndeterminate {
		t.Fatalf("verdict = %v, want indeterminate", got)
	}
}
