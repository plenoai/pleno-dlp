//go:build detector_unit

package akamai

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// High-entropy random-ish base64 secret, shaped like a real EdgeGrid
// client_secret.
const dummy = "aB3xK9pQ7vR2mZ8tN5wL1cF4dH6jY0sU+gE2bX7nM9kP3qT"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Akamai {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

// True positive 1: structured .edgerc form is accepted with high confidence.
func TestFromData_EdgercForm(t *testing.T) {
	body := []byte("[default]\nclient_secret = " + dummy + "\nhost = akab-xyz.luna.akamaiapis.net")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 from .edgerc form, got %d", len(res))
	}
}

// True positive 2: windowed fallback with assignment anchor + entropy.
func TestFromData_WindowedPositive(t *testing.T) {
	body := []byte("# akamai\nAKAMAI_CLIENT_SECRET=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1 from windowed fallback, got 0")
	}
}

// FP suppressed 1: a git SHA / hex ETag adjacent to the word akamai.
func TestFromData_HexLookalikeSuppressed(t *testing.T) {
	// 40-char hex (git SHA shape) plus a longer hex content hash.
	body := []byte("akamai client_secret reference 5f3a9c7e1b2d4f6a8c0e2d4f6a8c0e2d4f6a8c0e")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected hex lookalike suppressed, got %d", len(res))
	}
}

// FP suppressed 2: an Akamai cookie value on a Set-Cookie line.
func TestFromData_CookieLineSuppressed(t *testing.T) {
	body := []byte("Set-Cookie: ak_bmsc=" + dummy + "; Path=/; akamai")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected cookie-line value suppressed, got %d", len(res))
	}
}

// FP suppressed 3: a long base64 token sitting in a URL path.
func TestFromData_URLPathSuppressed(t *testing.T) {
	body := []byte("akamai asset edgegrid https://cdn.example.com/" + dummy + "/main.js")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected URL-path token suppressed, got %d", len(res))
	}
}

// FP suppressed 4: bare `akamai` mention without an assignment anchor no
// longer admits a generic high-entropy token.
func TestFromData_BareKeywordSuppressed(t *testing.T) {
	body := []byte("akamai is our CDN provider and the build artifact is " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected bare-keyword token suppressed, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("client_secret=" + dummy + "\nclient_secret=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_TooShort(t *testing.T) {
	body := []byte("client_secret=short")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}
