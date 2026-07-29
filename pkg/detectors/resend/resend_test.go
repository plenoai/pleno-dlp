//go:build detector_unit

package resend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "re_AbCdEf01_23456789AbCdEf0123456789"
const legacyDummy = "re_AbCdEf0123456789AbCdEf0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Resend {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("key="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_PreservesUnfamiliarPrefixCandidate(t *testing.T) {
	body := []byte("key=" + legacyDummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected candidate to be preserved, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("noise=abcdef0123456789"))
	if len(res) != 0 {
		t.Fatalf("expected 0 without re_ prefix, got %d", len(res))
	}
}

func TestFromData_VerificationSelectionPreservesCandidates(t *testing.T) {
	const identifier = "re_customer_record_archive_status"
	tests := []struct {
		name         string
		body         string
		wantRequests int
	}{
		{
			name:         "documented current shape",
			body:         "key=" + dummy,
			wantRequests: 1,
		},
		{
			name:         "unfamiliar mixed-case identifier shape",
			body:         "key=re_customer_Record_archive_status",
			wantRequests: 1,
		},
		{
			name:         "unfamiliar lowercase shape without separator",
			body:         "key=re_abcdefghijklmnopqrstuvwxyz",
			wantRequests: 1,
		},
		{
			name:         "unfamiliar lowercase shape with one separator",
			body:         "key=re_abcdefghijkl_mnopqrstuvwxyz",
			wantRequests: 1,
		},
		{
			name: "context does not override identifier shape",
			body: "RESEND_API_KEY=" + identifier,
		},
		{
			name: "contextless identifier shape",
			body: "key=" + identifier,
		},
		{
			name: "contextless identifier shape with digits",
			body: "key=re_customer_record_2026_archive",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"name":"invalid_api_key"}`))
			}))
			defer srv.Close()
			old := apiBase
			apiBase = srv.URL
			defer func() { apiBase = old }()

			withoutVerify, err := Scanner{}.FromData(context.Background(), false, []byte(tc.body))
			if err != nil {
				t.Fatalf("without verify: %v", err)
			}
			withVerify, err := Scanner{}.FromData(context.Background(), true, []byte(tc.body))
			if err != nil {
				t.Fatalf("with verify: %v", err)
			}
			if len(withoutVerify) != 1 || len(withVerify) != 1 {
				t.Fatalf("candidate count changed: without=%d with=%d", len(withoutVerify), len(withVerify))
			}
			if string(withoutVerify[0].Raw) != string(withVerify[0].Raw) {
				t.Fatal("candidate identity changed during verification")
			}
			if requests != tc.wantRequests {
				t.Fatalf("provider requests = %d, want %d", requests, tc.wantRequests)
			}
		})
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "re_AbCdE") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("User-Agent") != "pleno-dlp" {
			t.Errorf("user agent mismatch: %q", r.Header.Get("User-Agent"))
		}
		w.WriteHeader(http.StatusOK)
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

func TestVerify_ProviderVerdicts(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		want    bool
		wantErr bool
	}{
		{
			name:   "sending-only key remains valid",
			status: http.StatusUnauthorized,
			body:   `{"name":"restricted_api_key"}`,
			want:   true,
		},
		{
			name:   "invalid key is clean negative",
			status: http.StatusForbidden,
			body:   `{"name":"invalid_api_key"}`,
		},
		{
			name:    "invalid name with unauthorized status is indeterminate",
			status:  http.StatusUnauthorized,
			body:    `{"name":"invalid_api_key"}`,
			wantErr: true,
		},
		{
			name:    "restricted name with forbidden status is indeterminate",
			status:  http.StatusForbidden,
			body:    `{"name":"restricted_api_key"}`,
			wantErr: true,
		},
		{
			name:    "rate limit is indeterminate",
			status:  http.StatusTooManyRequests,
			body:    `{"name":"rate_limit_exceeded"}`,
			wantErr: true,
		},
		{
			name:    "server error is indeterminate",
			status:  http.StatusInternalServerError,
			body:    `{"name":"internal_server_error"}`,
			wantErr: true,
		},
		{
			name:    "unexpected auth response is indeterminate",
			status:  http.StatusUnauthorized,
			body:    `{"name":"missing_api_key"}`,
			wantErr: true,
		},
		{
			name:    "malformed response is indeterminate",
			status:  http.StatusForbidden,
			body:    `not-json`,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			old := apiBase
			apiBase = srv.URL
			defer func() { apiBase = old }()

			got, err := Scanner{}.Verify(context.Background(), dummy)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("verified = %v, want %v", got, tc.want)
			}
		})
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
