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

func TestFromData_RejectsCamelCaseIdentifier(t *testing.T) {
	// A Go CamelCase identifier within 256 bytes of a credential keyword
	// must NOT fire — entropy ≥ 4.0 but it's source code, not a secret.
	// Real example from aws-sdk-go-v2/aws/credentials.go.
	chunk := []byte(`// CredentialsCache provides caching for credentials.
type CredentialsCache struct {
	provider CredentialsProvider
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		if strings.Contains(string(r.Raw), "Credentials") {
			t.Errorf("CamelCase identifier must NOT match; got %q", r.Raw)
		}
	}
}

func TestFromData_RejectsImportPath(t *testing.T) {
	// Go import path embedded near `credential` keyword.
	chunk := []byte(`// credential helpers from "github.com/aws/aws-sdk-go-v2/aws/credentials"`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		if strings.Contains(string(r.Raw), "com/aws") {
			t.Errorf("import path must NOT match; got %q", r.Raw)
		}
	}
}

func TestLooksLikeIdentifier(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"CredentialProviderOptions", true},      // CamelCase Go ident
		{"UserAgentFeatureResourceModel", true},  // CamelCase Go ident
		{"TestSign_buildCanonicalHeaders", true}, // Go test ident with underscore
		{"AKIAIOSFODNN7EXAMPLE", false},          // AWS-style access key (has digit)
		{"Hf83KdjL9qZ8xVnB2Wm7TpRc", false},      // mixed case + digits → real-shaped
		{"ghp_aBcDeF123XYZ", false},              // has digits → real-shaped
		{"abc/def/ghi/jkl/mno", false},           // has `/`, disqualifies identifier
	}
	for _, c := range cases {
		if got := looksLikeIdentifier(c.s); got != c.want {
			t.Errorf("looksLikeIdentifier(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestLooksLikePath(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"com/aws/aws-sdk-go-v2", true},
		{"a/b/c", true},
		{"a/b", false}, // single slash — could be base64
		{"Hf83KdjL9qZ8xVnB2Wm7TpRc", false},
		{"path/with/slashes/here", true},
	}
	for _, c := range cases {
		if got := looksLikePath(c.s); got != c.want {
			t.Errorf("looksLikePath(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestLooksLikeSRIHash(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"sha256-RFWPLDbv2BY+rCkDzsE+0fr8ylQr2a", true},
		{"sha384-H8BRh8j48O9oYatfu5AZzq9to9wNipiB", true},
		{"sha512-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K", true},
		{"SHA256-uppercaseprefix", true},
		{"Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01", false},
		{"AKIAIOSFODNN7EXAMPLE0000000000000", false},
	}
	for _, c := range cases {
		if got := looksLikeSRIHash(c.s); got != c.want {
			t.Errorf("looksLikeSRIHash(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestLooksLikeHexDigest(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", true},                                                             // MD5 (32)
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", true},                                                      // SHA-1 (40)
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},                              // SHA-256 (64)
		{"Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01", false},                                             // non-hex chars
		{"a1b2c3d4e5f6a1b2c3d4", false},                                                                         // 20 chars, not a standard digest length
		{"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1", false},                             // 63 chars, not standard
		{"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5", false},                                                          // 35 chars
		{"DEADBEEFDEADBEEFDEADBEEFDEADBEEF", true},                                                               // uppercase hex, MD5 length
	}
	for _, c := range cases {
		if got := looksLikeHexDigest(c.s); got != c.want {
			t.Errorf("looksLikeHexDigest(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

func TestFromData_RejectsSRIHash(t *testing.T) {
	// npm package-lock.json integrity field: should not fire even though
	// "integrity" is near "password" from an unrelated section.
	chunk := []byte(`{
  "password": "exampleSensitiveNear",
  "integrity": "sha512-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/eO0EQ3HjgL1WxQvGKYfh8hqQRk="
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		raw := string(r.Raw)
		if strings.HasPrefix(strings.ToLower(raw), "sha") {
			t.Errorf("SRI hash must NOT fire; got %q", raw)
		}
	}
}

func TestFromData_RejectsHexDigestInLockfile(t *testing.T) {
	// composer.lock-style hash near a keyword; the hex digest should be suppressed.
	chunk := []byte(`{
  "auth": "token",
  "hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	for _, r := range res {
		if string(r.Raw) == "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
			t.Errorf("hex digest in hash context must NOT fire; got %q", r.Raw)
		}
	}
}

func TestFromData_StillFiresOnRealSecret(t *testing.T) {
	// A real-looking API key near a keyword must still be detected even when
	// an SRI hash appears elsewhere in the chunk.
	chunk := []byte(`{
  "integrity": "sha256-abc123",
  "api_key": "Hf83KdjL9qZ8xVnB2Wm7TpRcJyXuAbCdEfGhIjKlMnOp01"
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	found := false
	for _, r := range res {
		if strings.Contains(string(r.Raw), "Hf83KdjL9qZ8") {
			found = true
		}
	}
	if !found {
		t.Error("real API key must still fire even when SRI hash is in the same chunk")
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
