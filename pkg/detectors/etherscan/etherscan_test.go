//go:build detector_unit

package etherscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "ABCDEF0123456789ABCDEF0123456789AB"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Etherscan {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("ETHERSCAN_API_KEY=" + dummy)
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

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.Path != "/v2/api" {
			t.Errorf("path = %s, want /v2/api", r.URL.Path)
		}
		if r.URL.Query().Get("chainid") != "1" {
			t.Errorf("chainid mismatch")
		}
		if r.URL.Query().Get("module") != "stats" {
			t.Errorf("module mismatch")
		}
		if r.URL.Query().Get("action") != "ethsupply" {
			t.Errorf("action mismatch")
		}
		if r.URL.Query().Get("apikey") != dummy {
			t.Errorf("apikey mismatch")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"1","message":"OK","result":"120000000000000000000000000"}`))
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

func TestVerify_InvalidKeyInHTTP200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"0","message":"NOTOK","result":"Invalid API Key"}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("expected authoritative rejection, got err=%v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_IndeterminateResponses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "rate limited",
			status: http.StatusTooManyRequests,
			body:   `{"status":"0","message":"NOTOK","result":"rate limited"}`,
		},
		{
			name:   "server error",
			status: http.StatusInternalServerError,
			body:   `{"status":"0","message":"NOTOK","result":"server error"}`,
		},
		{
			name:   "malformed JSON",
			status: http.StatusOK,
			body:   `{"status":`,
		},
		{
			name:   "ambiguous provider response",
			status: http.StatusOK,
			body:   `{"status":"0","message":"NOTOK","result":"Max rate limit reached"}`,
		},
		{
			name:   "missing documented result",
			status: http.StatusOK,
			body:   `{"status":"1","message":"OK"}`,
		},
		{
			name:   "ambiguous HTTP status",
			status: http.StatusTeapot,
			body:   `{}`,
		},
		{
			name:   "undocumented unauthorized status",
			status: http.StatusUnauthorized,
			body:   `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			old := apiBase
			apiBase = srv.URL
			defer func() { apiBase = old }()

			v, err := Scanner{}.Verify(context.Background(), dummy)
			if v {
				t.Fatal("expected verified=false")
			}
			if err == nil {
				t.Fatal("expected indeterminate verification error")
			}
		})
	}
}

func TestVerify_ResponseBodyIsBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat(" ", 64*1024+1)))
		_, _ = w.Write([]byte(`{"status":"1","message":"OK","result":"1"}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
	if err == nil {
		t.Fatal("expected oversized response error")
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

	results, err := Scanner{}.FromData(context.Background(), true, []byte("etherscan="+dummy))
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

func TestVerify_TransportErrorDoesNotExposeAPIKey(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err == nil {
		t.Fatalf("transport failure = (verified=%v, err=%v), want indeterminate", v, err)
	}
	if strings.Contains(err.Error(), dummy) {
		t.Fatal("transport error exposed the API key")
	}
}
