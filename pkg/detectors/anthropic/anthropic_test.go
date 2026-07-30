//go:build detector_unit

package anthropic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var dummyKey = "sk-ant-api03-" + strings.Repeat("a", 93) + "AA"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("ANTHROPIC_API_KEY="+dummyKey))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyKey {
		t.Errorf("Raw = %q", res[0].Raw)
	}
}

func TestFromData_Negative_OpenAI(t *testing.T) {
	openai := "sk-abcdefghijklmnopqrstuvwxyz0123456789"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("key="+openai))
	if len(res) != 0 {
		t.Fatalf("expected 0 (openai must not match anthropic), got %d", len(res))
	}
}

func TestFromData_RejectsBroadLegacyShape(t *testing.T) {
	broadLegacyShape := "sk-ant-" + strings.Repeat("a", 40)
	res, err := Scanner{}.FromData(context.Background(), false, []byte("ANTHROPIC_API_KEY="+broadLegacyShape))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected broad legacy shape to be rejected, got %d", len(res))
	}
}

func TestFromData_RejectsWrongLength(t *testing.T) {
	wrongLength := "sk-ant-api03-" + strings.Repeat("a", 92) + "AA"
	res, err := Scanner{}.FromData(context.Background(), false, []byte("ANTHROPIC_API_KEY="+wrongLength))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected wrong-length key to be rejected, got %d", len(res))
	}
}

func TestFromData_Negative_Empty(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("nothing here"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v1/models" {
			t.Errorf("path = %s, want /v1/models", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != dummyKey {
			t.Errorf("missing x-api-key: %q", r.Header.Get("x-api-key"))
		}
		if r.Header.Get("anthropic-version") == "" {
			t.Error("missing anthropic-version header")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"x"}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_ExplicitInvalidKey(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()
			old := apiBase
			apiBase = srv.URL
			defer func() { apiBase = old }()

			v, err := Scanner{}.Verify(context.Background(), dummyKey)
			if err != nil {
				t.Fatalf("expected authoritative rejection, got err=%v", err)
			}
			if v {
				t.Fatalf("expected verified=false on %d", status)
			}
		})
	}
}

func TestVerify_IndeterminateStatus(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			}))
			defer srv.Close()
			old := apiBase
			apiBase = srv.URL
			defer func() { apiBase = old }()

			v, err := Scanner{}.Verify(context.Background(), dummyKey)
			if v {
				t.Fatalf("expected verified=false on %d", status)
			}
			if err == nil {
				t.Fatalf("expected indeterminate verification error on %d", status)
			}
		})
	}
}

func TestVerify_TruncatedResponseIsIndeterminate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "10")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyKey)
	if v {
		t.Fatal("expected verified=false")
	}
	if err == nil {
		t.Fatal("expected truncated response error")
	}
}

func TestFromData_VerificationFailureIsIndeterminate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	results, err := Scanner{}.FromData(context.Background(), true, []byte("ANTHROPIC_API_KEY="+dummyKey))
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Verdict() != detectors.VerdictIndeterminate {
		t.Fatalf("verdict = %s, want indeterminate", results[0].Verdict())
	}
}
