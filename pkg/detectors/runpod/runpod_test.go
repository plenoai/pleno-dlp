//go:build detector_unit

package runpod

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "ABCDEFGH1234567890ABCDEFGH1234567890ABCD"

func TestFromData_Positive(t *testing.T) {
	body := []byte("# runpod\nRUNPOD_API_KEY=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "ABCDEFGH") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("auth mismatch")
		}
		if r.URL.Path != "/graphql" {
			t.Errorf("path: %q", r.URL.Path)
		}
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request method or content type")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != string(probeBody) {
			t.Errorf("unexpected probe body: %q, err: %v", body, err)
		}
		_, _ = io.WriteString(w, `{"data":{"myself":{"id":"synthetic-user"}}}`)
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
		t.Fatalf("explicit rejection should not be indeterminate: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
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

func TestVerify_InconclusiveResponsesRetainFinding(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"empty", http.StatusOK, ""},
		{"malformed", http.StatusOK, "not JSON"},
		{"null", http.StatusOK, "null"},
		{"missing data", http.StatusOK, `{}`},
		{"null data", http.StatusOK, `{"data":null}`},
		{"missing myself", http.StatusOK, `{"data":{}}`},
		{"null myself", http.StatusOK, `{"data":{"myself":null}}`},
		{"missing id", http.StatusOK, `{"data":{"myself":{}}}`},
		{"empty id", http.StatusOK, `{"data":{"myself":{"id":""}}}`},
		{"whitespace id", http.StatusOK, `{"data":{"myself":{"id":"  "}}}`},
		{"wrong id type", http.StatusOK, `{"data":{"myself":{"id":123}}}`},
		{"graphql error", http.StatusOK, `{"errors":[{"message":"` + dummy + `"}]}`},
		{"malformed errors", http.StatusOK, `{"data":{"myself":{"id":"synthetic-user"}},"errors":{}}`},
		{"partial data with error", http.StatusOK, `{"data":{"myself":{"id":"synthetic-user"}},"errors":[{"message":"denied"}]}`},
		{"trailing payload", http.StatusOK, `{"data":{"myself":{"id":"synthetic-user"}}}{}`},
		{"oversized", http.StatusOK, `{"data":{"myself":{"id":"synthetic-user"}},"padding":"` + strings.Repeat("x", 64<<10) + `"}`},
		{"forbidden", http.StatusForbidden, ""},
		{"rate limited", http.StatusTooManyRequests, ""},
		{"provider error", http.StatusInternalServerError, ""},
		{"service unavailable", http.StatusServiceUnavailable, ""},
		{"unexpected status", http.StatusNotFound, ""},
		{"redirect", http.StatusFound, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			old := apiBase
			apiBase = srv.URL
			defer func() { apiBase = old }()

			results, err := (Scanner{}).FromData(context.Background(), true, []byte("runpod "+dummy))
			if err != nil || len(results) != 1 {
				t.Fatalf("potential secret was dropped: results=%d, err=%v", len(results), err)
			}
			result := results[0]
			if result.Verified || result.VerificationErr == nil || result.Verdict() != detectors.VerdictIndeterminate {
				t.Fatalf("expected indeterminate finding, got verified=%v, error=%v", result.Verified, result.VerificationErr)
			}
			if string(result.Raw) != dummy || result.Redacted != redact(dummy) {
				t.Fatal("finding data changed")
			}
			if strings.Contains(result.VerificationErr.Error(), dummy) {
				t.Fatal("verification error leaked provider response content")
			}
		})
	}
}

func TestFromData_CancelledVerificationRetainsFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("cancelled verification must not reach server")
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results, err := (Scanner{}).FromData(ctx, true, []byte("runpod "+dummy))
	if err != nil || len(results) != 1 {
		t.Fatalf("potential secret was dropped: results=%d, err=%v", len(results), err)
	}
	if results[0].Verdict() != detectors.VerdictIndeterminate {
		t.Fatal("expected indeterminate finding after cancellation")
	}
}
