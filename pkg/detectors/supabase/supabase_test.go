//go:build detector_unit

package supabase

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func mintJWT(t *testing.T, claims map[string]string) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, _ := json.Marshal(claims)
	pl := base64.RawURLEncoding.EncodeToString(body)
	sig := base64.RawURLEncoding.EncodeToString([]byte("padding-padding-padding-bytes-bytes-bytes"))
	return hdr + "." + pl + "." + sig
}

func TestFromData_ServiceRole_Critical(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"role": "service_role",
		"ref":  "abcdefghijklmnopqrst",
		"iss":  "supabase",
	})
	body := []byte("# supabase\nSUPABASE_SERVICE_ROLE_KEY=" + tok + "\nSUPABASE_URL=https://abcdefghijklmnopqrst.supabase.co")
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("expected SeverityCritical for service_role, got %v", res[0].Severity)
	}
	if res[0].ExtraData["role"] != "service_role" {
		t.Fatalf("role mismatch: %q", res[0].ExtraData["role"])
	}
	if res[0].ExtraData["project_ref"] != "abcdefghijklmnopqrst" {
		t.Fatalf("project_ref capture missing: %q", res[0].ExtraData["project_ref"])
	}
}

func TestFromData_AnonKey_High(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"role": "anon",
		"ref":  "abcdefghijklmnopqrst",
	})
	body := []byte("# supabase\nNEXT_PUBLIC_SUPABASE_ANON_KEY=" + tok)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Severity == detectors.SeverityCritical {
		t.Fatalf("anon key should not be Critical, got %v", res[0].Severity)
	}
}

func TestFromData_NotSupabase(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"sub": "111",
		"iss": "https://accounts.google.com",
	})
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("# supabase\nX="+tok))
	if len(res) != 0 {
		t.Fatalf("non-supabase JWT must not be claimed; got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	tok := mintJWT(t, map[string]string{
		"role": "service_role",
	})
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+tok))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

// withAPIBase overrides the package host for the duration of a test.
func withAPIBase(t *testing.T, url string) {
	t.Helper()
	prev := apiBase
	apiBase = url
	t.Cleanup(func() { apiBase = prev })
}

func serviceRoleChunk(t *testing.T) []byte {
	tok := mintJWT(t, map[string]string{
		"role": "service_role",
		"ref":  "abcdefghijklmnopqrst",
		"iss":  "supabase",
	})
	return []byte("# supabase\nSUPABASE_SERVICE_ROLE_KEY=" + tok)
}

func TestVerify_Accept200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/v1/" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Header.Get("apikey") == "" {
			t.Error("missing apikey header")
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("missing Bearer auth: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	res, err := Scanner{}.FromData(context.Background(), true, serviceRoleChunk(t))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified || res[0].VerificationErr != nil {
		t.Fatalf("expected verified=true err=nil, got verified=%v err=%v", res[0].Verified, res[0].VerificationErr)
	}
}

func TestVerify_Reject401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	res, err := Scanner{}.FromData(context.Background(), true, serviceRoleChunk(t))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res[0].Verified {
		t.Fatal("expected verified=false on 401")
	}
	if res[0].VerificationErr != nil {
		t.Fatalf("401 is an authoritative rejection, not an error: %v", res[0].VerificationErr)
	}
}

func TestVerify_Reject403(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	res, _ := Scanner{}.FromData(context.Background(), true, serviceRoleChunk(t))
	if res[0].Verified {
		t.Fatal("expected verified=false on 403")
	}
	if res[0].VerificationErr != nil {
		t.Fatalf("403 must not surface as transient error: %v", res[0].VerificationErr)
	}
}

func TestVerify_Transient500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	res, _ := Scanner{}.FromData(context.Background(), true, serviceRoleChunk(t))
	if res[0].Verified {
		t.Fatal("expected verified=false on 500")
	}
	if res[0].VerificationErr == nil {
		t.Fatal("expected transient VerificationErr on 500")
	}
}

func TestVerify_Transient429(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	res, _ := Scanner{}.FromData(context.Background(), true, serviceRoleChunk(t))
	if res[0].Verified {
		t.Fatal("expected verified=false on 429")
	}
	if res[0].VerificationErr == nil {
		t.Fatal("expected transient VerificationErr on 429")
	}
}

func TestVerify_NoRefNoOp(t *testing.T) {
	// No apiBase override and no ref claim/URL → Verify must no-op rather
	// than probe a wrong tenant.
	tok := mintJWT(t, map[string]string{"role": "service_role"})
	v, err := Scanner{}.Verify(context.Background(), tok)
	if v || err != nil {
		t.Fatalf("expected (false,nil) no-op, got (%v,%v)", v, err)
	}
}

func TestRedact(t *testing.T) {
	tok := mintJWT(t, map[string]string{"role": "service_role"})
	r := redact(tok)
	if r == tok {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "eyJ") {
		t.Fatalf("missing prefix: %q", r)
	}
}
