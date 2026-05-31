package lark

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyAppID = "cli_abcdef0123456789"
const dummySecret = "ABCDEFabcdef0123456789ZYXWVU0987"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Lark {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("LARK_APP_ID=" + dummyAppID + "\nLARK_APP_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
	if string(res[0].RawV2) == "" {
		t.Fatal("expected RawV2 to carry secret")
	}
}

func TestFromData_NoMatch(t *testing.T) {
	body := []byte("token=cli_short")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for malformed app_id, got %d", len(res))
	}
}

// Regression: a low-entropy 32-char run (a repetitive hex-ish blob, entropy
// ~2.16 bits/char) sitting right next to a valid app_id must no longer be
// promoted to an app_secret. Before the entropy gate the bare
// [A-Za-z0-9]{32} regex accepted this shape.
func TestFromData_RejectsLowEntropySecret(t *testing.T) {
	const lowEntropyBlob = "deadbeefdeadbeefdeadbeefdeadbeef" // entropy ~2.16
	body := []byte("lark_app_id=" + dummyAppID + "\nlark_app_secret=" + lowEntropyBlob)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy secret, got %d", len(res))
	}
}

// Regression: the keyword gate must no longer arm on a bare provider mention.
// An app_id whose only nearby context (radius 64) is the English word
// "coherent"... er, an unrelated sentence containing "lark" the bird, with no
// assignment marker and no cli_ shape within 64 bytes, must not arm. The
// app_id itself is cli_-shaped so it self-arms via contextRe; to exercise the
// radius shrink we use a non-cli_-prefixed false app_id candidate is not
// possible (appIDRe requires cli_), so instead we assert the arm regex itself
// rejects a bare keyword window.
func TestContextRe_RejectsBareKeyword(t *testing.T) {
	// Bare provider mention, no assignment marker, no cli_ app_id shape.
	if contextRe.MatchString("the meadowlark sang near the larkspur field") {
		t.Fatal("arm regex armed on a bare keyword substring; should require an assignment marker or cli_ shape")
	}
	// Assignment-style markers must still arm.
	for _, s := range []string{"lark_app_secret", "feishu-app-id", "LARK_APP_TOKEN", "lark_key", "cli_abcdef0123456789"} {
		if !contextRe.MatchString(s) {
			t.Fatalf("arm regex failed to arm on %q", s)
		}
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyAppID+":"+dummySecret)
	if err != nil || !v {
		t.Fatalf("expected verified=true: err=%v v=%v", err, v)
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"code":10003,"msg":"invalid app_id"}`))
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummyAppID+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyAppID+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false on 5xx")
	}
}
