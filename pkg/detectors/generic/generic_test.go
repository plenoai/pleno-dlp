package generic

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestFromData_FiresNearKeyword(t *testing.T) {
	// 50-char base64-shaped token with high entropy adjacent to api_key.
	chunk := []byte(`config:
  database_url: postgres://localhost
  api_key = "Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01"
`)
	res, err := Scanner{}.FromData(context.Background(), false, chunk)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("expected at least one finding")
	}
	if res[0].DetectorType != detectors.GenericHighEntropy {
		t.Errorf("wrong type: %v", res[0].DetectorType)
	}
	if !strings.Contains(string(res[0].Raw), "Hf83KdjL9qZ8") {
		t.Errorf("captured wrong span: %q", res[0].Raw)
	}
}

func TestFromData_RejectsLowEntropy(t *testing.T) {
	// 60 zeros next to api_key — passes regex, fails entropy gate.
	chunk := []byte(`api_key=000000000000000000000000000000000000000000000000000000000000`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	if len(res) != 0 {
		t.Fatalf("expected zero hits on all-zeros, got %d (raw=%q)", len(res), res[0].Raw)
	}
}

func TestFromData_RejectsHighEntropyWithoutKeyword(t *testing.T) {
	// High-entropy random string without any credential keyword nearby.
	// Should not fire — the keyword gate is the whole point.
	chunk := []byte(`commit abc123def456ghi789jkl012mno345pqr678stu901vwx234yz5
files: 42
`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	if len(res) != 0 {
		t.Fatalf("expected zero hits without keyword, got %d", len(res))
	}
}

func TestFromData_RejectsKeywordTooFar(t *testing.T) {
	// api_key keyword more than 256 bytes from the entropy run.
	prefix := "api_key=safe-public-value\n"
	gap := strings.Repeat("a non-secret line of plain text\n", 12) // ~360 bytes
	suffix := `  hidden = "Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01"`
	chunk := []byte(prefix + gap + suffix)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		if strings.Contains(string(r.Raw), "Hf83KdjL9qZ8") {
			t.Errorf("entropy run far from keyword must NOT match; got %q", r.Raw)
		}
	}
}

func TestFromData_DedupsSameSecret(t *testing.T) {
	// Same high-entropy secret appearing twice within a chunk should
	// dedup at the detector level (engine dedup is a separate layer
	// keyed on location too — here we just confirm we don't double-emit
	// from one chunk.)
	secret := "Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01"
	chunk := []byte("api_key=" + secret + "\nfallback_token=" + secret)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestRedact_StableShape(t *testing.T) {
	got := redact("Hf83KdjL9qZ8xVnB2Wm7TpRc")
	if got != "Hf83..." {
		t.Errorf("redact: %q", got)
	}
	if redact("abc") != "abc" {
		t.Error("short strings shouldn't be ellipsised")
	}
}

func TestKeywords_NotEmpty(t *testing.T) {
	kws := Scanner{}.Keywords()
	if len(kws) < 5 {
		t.Fatalf("expected substantial keyword list, got %d", len(kws))
	}
	// Every keyword must already be lowercase — engine matches case-
	// insensitively but we promise to ship lowercase.
	for _, kw := range kws {
		if kw != strings.ToLower(kw) {
			t.Errorf("keyword %q must be lowercase", kw)
		}
	}
}

func TestShannonEntropy_CalibratesAtFour(t *testing.T) {
	// Sanity-check the threshold: random-looking strings score above 4.0,
	// repetitive strings score well below.
	if e := shannonEntropy("Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01"); e < 4.0 {
		t.Errorf("random b64 must score >= 4.0, got %v", e)
	}
	if e := shannonEntropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); e > 1.0 {
		t.Errorf("all-same-char must score < 1.0, got %v", e)
	}
}
