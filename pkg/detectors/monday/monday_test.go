//go:build detector_unit

package monday

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "eyJhbGciOiJIUzI1NiJ9.eyJ0aWQiOjEyMzQ1Njc4OSwiYWFpIjoxMSwidWlkIjoxMDAwMDAsImlhZCI6IjIwMjQtMDEtMDFUMDA6MDA6MDAuMDAwWiIsInBlciI6Im1lOndyaXRlIiwiYWN0aWQiOjEsInJnbiI6InVzZTEifQ.dummysig0123456"

func TestFromData_Positive(t *testing.T) {
	body := []byte("# monday.com\nMONDAY_API_TOKEN=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "eyJhbGciOiJI") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != dummy {
			t.Errorf("auth mismatch")
		}
		if r.Method != http.MethodPost {
			t.Errorf("method: %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"me":{"id":"123"}}}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_HTTP200GraphQLErrorRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":null,"errors":[{"message":"Not Authenticated"}]}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil || v {
		t.Fatalf("GraphQL error = (verified=%v, err=%v), want indeterminate", v, err)
	}
}

func TestVerify_HTTP200InvalidIdentityTypeIsIndeterminate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"me":{"id":{"unexpected":true}}}}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil || v {
		t.Fatalf("invalid identity = (verified=%v, err=%v), want indeterminate", v, err)
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
		_, _ = w.Write([]byte(strings.Repeat(" ", (64<<10)+1) + `{"data":{"me":{"id":"123"}}}`))
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

func TestVerify_RateLimitIsIndeterminate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("rate limit must be indeterminate")
	}
	if v {
		t.Fatal("rate limit must not verify")
	}
}

func TestVerify_ServerErrorIsIndeterminate(t *testing.T) {
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
		t.Fatal("server error must not verify")
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
		[]byte("MONDAY_API_TOKEN="+dummy),
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

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}

// --- False-positive regressions ---

// FP-1: JWT near the word "monday" as a weekday reference must not fire.
// Previously the "monday " (trailing space) keyword matched casual English.
func TestFromData_FP_WeekdayMention(t *testing.T) {
	body := []byte("# meeting on monday \nticket=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("weekday FP: expected 0, got %d", len(res))
	}
}

// FP-2: generic JWT near "monday" in prose must not fire without a
// Monday.com-specific keyword.
func TestFromData_FP_GenericJWTNearMonday(t *testing.T) {
	// A JWT from an unrelated service in a comment mentioning the weekday.
	body := []byte("# deployed last monday\ntoken=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("generic-JWT-near-monday FP: expected 0, got %d", len(res))
	}
}
