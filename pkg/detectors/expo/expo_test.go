//go:build detector_unit

package expo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// 32-char [A-Za-z0-9_-] — matches the real Expo PAT shape.
const dummy = "abcdef0123456789ABCDEF_-abcdef01"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Expo {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("EXPO_TOKEN=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_FoundEASToken(t *testing.T) {
	body := []byte("EAS_TOKEN=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 for EAS_TOKEN")
	}
}

func TestFromData_FoundExpoDevURL(t *testing.T) {
	body := []byte("curl https://expo.dev/api -H 'Authorization: Bearer " + dummy + "'")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 when expo.dev is in context")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// --- False-positive regressions reported by users -----------------

// FP-1: `export const x = "..."` — the bare letters e-x-p-o appear
// inside the word "export". The old detector matched
// strings.Contains(window, "expo") and fired on every 30-40 char
// alphanumeric blob in the file. The new detector must reject.
func TestFromData_FP_ExportKeyword(t *testing.T) {
	// 32-char hex string — looks like an Expo PAT but is just a
	// hash literal next to the word "export".
	body := []byte(`export const apiKey = "abcdef0123456789abcdef0123456789";`)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("export-keyword FP: expected 0, got %d (%+v)", len(res), res)
	}
}

// FP-2: 40-char git SHA in a commit log. Even if "expo" letters
// appear in the surrounding prose ("expose", "export", etc.) the
// detector must not fire. We test with a true 40-char SHA which is
// out of the new fixed-length-32 regex anyway, plus a 32-char hex
// hash adjacent to "exposure" prose.
func TestFromData_FP_GitSHA(t *testing.T) {
	body := []byte(`commit abcdef0123456789abcdef0123456789abcdef00
Author: someone
    exposing internal helper`)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("git-SHA + exposing FP: expected 0, got %d", len(res))
	}
}

// FP-3: "exposure" prose near a 32-char hash.
func TestFromData_FP_ExposureProse(t *testing.T) {
	body := []byte(`# exposure: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("exposure-prose FP: expected 0, got %d", len(res))
	}
}

// FP-4: npm sha512 / lockfile hash dump.
func TestFromData_FP_NpmHashDump(t *testing.T) {
	body := []byte(`integrity sha512-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==
resolved "https://registry.npmjs.org/express/-/express-4.18.2.tgz"`)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("npm hash FP: expected 0, got %d", len(res))
	}
}

// FP-5: "exponent" prose — historical Expo company name was
// "Exponent", so this is a particularly nasty FP source.
func TestFromData_FP_ExponentProse(t *testing.T) {
	body := []byte(`// exponent backoff using token bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("exponent-prose FP: expected 0, got %d", len(res))
	}
}

// --- Verify (unchanged) -------------------------------------------

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("missing auth header")
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
