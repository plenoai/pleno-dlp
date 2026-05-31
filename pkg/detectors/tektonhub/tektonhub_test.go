package tektonhub

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a high-entropy mixed-case base62 blob (not pure-hex, not 64-char
// hex) of 40 chars.
const dummy = "AbC9XfQ2zR7mKpLs0123456789AbCdEfGhJkLmNp"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.TektonHub {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

// TestFromData_Positive: a true-positive that is STILL detected — an explicit
// token-specific assignment.
func TestFromData_Positive(t *testing.T) {
	body := []byte("# tekton\nTEKTON_HUB_TOKEN=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

// TestFromData_PositiveQuotedBearer: still detected with a quoted Authorization
// bearer assignment.
func TestFromData_PositiveQuotedBearer(t *testing.T) {
	body := []byte(`authorization: "Bearer ` + dummy + `"`)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

// TestFromData_FP_ImageDigest: a Tekton TaskRun referencing a 64-char hex image
// digest near the word `tekton` is now SUPPRESSED (pure-hex + no token keyword).
func TestFromData_FP_ImageDigest(t *testing.T) {
	body := []byte("# tekton.dev/v1 TaskRun\n" +
		"image: registry.io/build@sha256:5d41402abc4b2a76b9719d911017c592aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected image digest suppressed, got %d", len(res))
	}
}

// TestFromData_FP_GitRevision: a git revision/commit hex near a tekton Pipeline
// is now SUPPRESSED.
func TestFromData_FP_GitRevision(t *testing.T) {
	body := []byte("apiVersion: tekton.dev/v1\nkind: Pipeline\n" +
		"revision: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b3b3b3b3b3b3b3b3b3b3b3b3b\n")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected git revision suppressed, got %d", len(res))
	}
}

// TestFromData_FP_NoTokenKeyword: a generic base62 blob assigned to a non-token
// field near `tekton` is SUPPRESSED — the keyword gate no longer matches the
// broad `tekton` window.
func TestFromData_FP_NoTokenKeyword(t *testing.T) {
	body := []byte("# tekton\nuid: " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected non-token field suppressed, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("hub_token=" + dummy + "\nhub_token=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
}
