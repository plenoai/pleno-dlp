//go:build detector_unit

package teamcity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "eyJfaWQiOiJUZWFtY2l0eVRva2VuLTEyMzQ1IiwidiI6MX0.AbCdEf0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.TeamCity {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# teamcity\nTEAMCITY_TOKEN=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("teamcity=" + dummy + "\nteamcity=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

// withAPIBase points apiBase at an httptest server for the duration of a test.
func withAPIBase(t *testing.T, url string) {
	t.Helper()
	prev := apiBase
	apiBase = url
	t.Cleanup(func() { apiBase = prev })
}

func TestVerify_NoAPIBase_NoOp(t *testing.T) {
	withAPIBase(t, "")
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if v || err != nil {
		t.Fatalf("expected no-op (false,nil) without apiBase, got (%v,%v)", v, err)
	}
}

func TestVerify_Accept200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+dummy {
			t.Errorf("unexpected auth header: %q", got)
		}
		if r.URL.Path != "/app/rest/server" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
	}
}

func TestVerify_Reject(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		withAPIBase(t, srv.URL)
		v, err := Scanner{}.Verify(context.Background(), dummy)
		srv.Close()
		if v {
			t.Fatalf("code %d: expected verified=false", code)
		}
		if err != nil {
			t.Fatalf("code %d: expected nil err on explicit rejection, got %v", code, err)
		}
	}
}

func TestVerify_TransientErr(t *testing.T) {
	for _, code := range []int{http.StatusInternalServerError, http.StatusTooManyRequests} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))
		withAPIBase(t, srv.URL)
		v, err := Scanner{}.Verify(context.Background(), dummy)
		srv.Close()
		if v {
			t.Fatalf("code %d: expected verified=false", code)
		}
		if err == nil {
			t.Fatalf("code %d: expected transient err, got nil", code)
		}
	}
}

func TestFromData_VerifySetsResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	withAPIBase(t, srv.URL)

	body := []byte("# teamcity\nTEAMCITY_TOKEN=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), true, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if !res[0].Verified || res[0].VerificationErr != nil {
		t.Fatalf("expected verified result, got verified=%v err=%v", res[0].Verified, res[0].VerificationErr)
	}
}
