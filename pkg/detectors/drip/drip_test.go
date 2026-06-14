//go:build detector_unit

package drip

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "abcdef0123456789ABCDEF0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Drip {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# getdrip\nDRIP_API_TOKEN=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
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
	// Two armed assignment lines carrying the same token must collapse to one.
	// (Fixture uses the assignment anchor because the gate now requires it; the
	// prior bare-"getdrip" form was the false-positive shape being removed.)
	body := []byte("drip_api_token=" + dummy + "\ndrip_api_token=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(dummy+":"))
		if r.Header.Get("Authorization") != want {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil || !v {
		t.Fatalf("verified expected true: err=%v v=%v", err, v)
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

// --- False-positive regressions ---

// FP-1: 32-char lowercase-hex git SHA prefix near getdrip must not fire.
func TestFromData_FP_GitSHAPrefix(t *testing.T) {
	body := []byte("getdrip # commit a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("git-SHA-prefix FP: expected 0, got %d (%+v)", len(res), res)
	}
}

// FP-2: npm lockfile integrity hash (lowercase hex) near drip keyword.
func TestFromData_FP_LockfileHash(t *testing.T) {
	body := []byte("# getdrip token\nintegrity sha256-00112233445566778899aabbccddeeff")
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("lockfile-hash FP: expected 0, got %d", len(res))
	}
}

// FP-3: a high-entropy, key-shaped 32-char alnum run that merely sits in the
// same chunk as a bare "getdrip" mention (no credential assignment anchor)
// must NOT fire. This is the false-positive shape the radius-256 +
// bare-strings.Contains gate accepted; the radius-64 assignment-anchor arm
// regex now rejects it. dummy is genuinely high entropy, so this proves the
// gate (not the entropy floor) is what culls it.
func TestFromData_FP_HighEntropyBareKeyword(t *testing.T) {
	// "getdrip" appears far from the token and with no token/key/secret anchor.
	body := []byte("see the getdrip changelog for details\n\nUNRELATED_VALUE=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("high-entropy-bare-keyword FP: expected 0, got %d (%+v)", len(res), res)
	}
}
