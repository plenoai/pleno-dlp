package jenkins

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a high-entropy 11<32-hex> shape used as a realistic token.
const dummy = "11abcdef0123456789abcdef0123456789"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Jenkins {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

// TestFromData_Positive: a credential assignment is STILL detected.
func TestFromData_Positive(t *testing.T) {
	body := []byte("# jenkins\nJENKINS_API_TOKEN=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatalf("expected >=1, got 0")
	}
}

// TestFromData_PositiveQuotedYAML: quoted key:value form still detected.
func TestFromData_PositiveQuotedYAML(t *testing.T) {
	body := []byte(`jenkins_token: "` + dummy + `"`)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 for quoted assignment, got %d", len(res))
	}
}

// TestFromData_NoKeyword: no jenkins context at all.
func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("jenkins_api_token=" + dummy + "\njenkins_api_token=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestFromData_BadShape(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("jenkins_api_token=22abcdef0123456789abcdef0123456789"))
	if len(res) != 0 {
		t.Fatalf("expected 0 (must start with 11), got %d", len(res))
	}
}

// --- FP suppression fixtures (now SUPPRESSED by the hardening) ---

// FP1: an artifact/content checksum near the bare word `jenkins`. Under the
// old 256-byte proximity gate this leaked; the assignment regex now
// requires a credential key, so it is suppressed.
func TestFromData_FP_ArtifactChecksum(t *testing.T) {
	body := []byte("jenkins build artifact sha: " + dummy + "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for artifact checksum near bare 'jenkins', got %d", len(res))
	}
}

// FP2: a content-addressed cache key in a pipeline log near `jenkins`.
func TestFromData_FP_CacheKey(t *testing.T) {
	body := []byte("JENKINS_WORKSPACE cache " + dummy + " restored")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for cache key near bare 'jenkins', got %d", len(res))
	}
}

// FP3: the token shape embedded as a slice of a longer 40-char git SHA next
// to a jenkins assignment-looking prefix — the closing \b fails, so no
// match. Guards the negative-lookalike rule.
func TestFromData_FP_GitSHASlice(t *testing.T) {
	body := []byte("jenkins git rev = " + dummy + "cafe00")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for 34-hex slice inside a longer hex run, got %d", len(res))
	}
}

// FP4: low-entropy hex that satisfies 11<32-hex> but is not a real token.
func TestFromData_FP_LowEntropy(t *testing.T) {
	// 11 + 32 zeros = 34 chars: passes the shape regex but fails entropy.
	body := []byte("jenkins_api_token=1100000000000000000000000000000000")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy hex, got %d", len(res))
	}
}
