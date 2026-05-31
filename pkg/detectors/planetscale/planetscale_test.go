package planetscale

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyID = "pscale_oauth_AbCdEf0123456789AbCdEf0123456789ABCD"
const dummySecret = "ZyXwVu9876543210ZyXwVu9876543210ZyXwVu98"

func TestFromData_Pair(t *testing.T) {
	body := []byte("# planetscale\nPSCALE_TOKEN_ID=" + dummyID + "\nPSCALE_TOKEN=" + dummySecret)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyID {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("rawv2 mismatch: %q", res[0].RawV2)
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("expected SeverityCritical")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummyID))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

// lowEntropySecret is a 40-char alnum run that clears the bare secret regex
// but is a structured/repetitive value, not a random token. With the entropy
// floor it must NOT be paired, so the id surfaces without a RawV2 secret.
const lowEntropySecret = "ABABABABABABABABABABABABABABABABABABABAB"

func TestFromData_LowEntropySecretRejected(t *testing.T) {
	body := []byte("# planetscale\nPSCALE_TOKEN_ID=" + dummyID + "\nPSCALE_TOKEN=" + lowEntropySecret)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 (id only), got %d", len(res))
	}
	if len(res[0].RawV2) != 0 {
		t.Fatalf("low-entropy secret should not pair, got RawV2=%q", res[0].RawV2)
	}
}

// TestFromData_BareKeywordRejected verifies the tightened arm gate: a bare
// `planetscale` mention (no `_token`-style reference) no longer arms the id.
func TestFromData_BareKeywordRejected(t *testing.T) {
	body := []byte("// see planetscale.com for docs\nID=" + dummyID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 with bare keyword only, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "pscale_oauth_A") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != dummyID+":"+dummySecret {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		if r.URL.Path != "/v1/organizations" {
			t.Errorf("path: %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
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

	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
