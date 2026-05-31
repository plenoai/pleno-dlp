package gocd

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a realistic GoCD token shape: 40-char mixed-case base62
// (contains chars outside [0-9a-f], so it is not a hex digest).
const dummy = "Zk9aP2qL7mZ3rT6yB1vN8wQ4eD5sG0hJ2cF7uK3a"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.GoCD {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# gocd\nGOCD_TOKEN=" + dummy)
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
	body := []byte("gocd " + dummy + "\ngocd " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_TooShort(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("gocd abc123"))
	if len(res) != 0 {
		t.Fatalf("expected 0 for short token, got %d", len(res))
	}
}

// TestFromData_FalsePositives asserts the hardening suppresses the
// dominant FP classes: 40-char git SHA-1 and 64-char SHA-256 digests in
// prose near `gocd`, and a base64 blob near a bare prose `gocd`.
func TestFromData_FalsePositives(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			// CHANGELOG line pinning a build image by git SHA-1.
			"git_sha1_near_gocd",
			"gocd: pin build image to da39a3ee5e6b4b0d3255bfef95601890afd80709",
		},
		{
			// SBOM / lockfile entry with a SHA-256 content digest.
			"sha256_near_gocd",
			"# gocd-agent sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			// Base64 blob in a doc that names GoCD outside the tight
			// weak-keyword window (prose mention, not a credential).
			"base64_blob_far_from_gocd",
			"This document describes the gocd pipeline architecture in detail; " +
				"an unrelated payload follows: aGVsbG93b3JsZGZvb2JhcmJhemFiY2RlZmdoaWprbG1ub3A end.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.body))
			if len(res) != 0 {
				t.Fatalf("expected 0 (suppressed FP), got %d: %v", len(res), res)
			}
		})
	}
}

// TestFromData_StrongAnchor confirms a true GoCD token next to an
// explicit credential anchor is still detected within strongRadius.
func TestFromData_StrongAnchor(t *testing.T) {
	tok := "Xk9aP2qL7mZ3rT6yB1vN8wQ4eD5sG0hJ2cF7uK3a"
	body := []byte("gocd_token = \"" + tok + "\"")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 for strong anchor, got %d", len(res))
	}
}
