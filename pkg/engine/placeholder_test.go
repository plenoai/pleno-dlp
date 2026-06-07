package engine

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestIsPlaceholder_Rejects(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		why  string
	}{
		{"aws-docs-example", "AKIAIOSFODNN7EXAMPLE", "AWS docs literal — substring EXAMPLE"},
		{"your-token-here", "YOUR_TOKEN_HERE", "templated placeholder — substring YOUR_TOKEN"},
		{"your-key", "YOUR_KEY", "templated placeholder — substring YOUR_KEY"},
		{"your-secret", "YOUR_SECRET", "templated placeholder — substring YOUR_SECRET"},
		{"angle-token", "<TOKEN>", "bracket-style placeholder"},
		{"angle-secret", "<SECRET>", "bracket-style placeholder"},
		{"angle-key", "<KEY>", "bracket-style placeholder"},
		{"placeholder", "PLACEHOLDER", "literal substring"},
		{"redacted-marker", "Bearer REDACTED here", "redaction marker embedded"},
		{"x-run-8", "AKIAXXXXXXXX1234", "8+ consecutive X"},
		{"x-run-12-lower", "abcdxxxxxxxxxxxx9999", "8+ consecutive x (case-insensitive)"},
		{"zero-run-10", "AKIA0000000000abcd", "10+ consecutive 0"},
		{"exact-dummy", "dummy", "exact match — single token"},
		{"exact-test-upper", "TEST", "exact match — case-insensitive"},
		{"exact-foo", "foo", "exact match"},
		{"exact-bar", "bar", "exact match"},
		{"exact-password", "password", "exact match"},
		{"exact-changeme", "ChangeMe", "exact match — case-insensitive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !IsPlaceholder([]byte(tc.raw)) {
				t.Fatalf("expected %q (%s) to be rejected as placeholder", tc.raw, tc.why)
			}
		})
	}
}

func TestIsPlaceholder_AcceptsRealLooking(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		why  string
	}{
		{"random-base64", "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA==", "uniformly-random base64; no marker, no run"},
		{"dummynet-not-dummy", "dummynet", "substring-of-exact-match must not trip exact path"},
		{"contains-test-substring", "testimonialsAccessKey42", "exact 'test' would gut every real token containing test"},
		{"contains-foo-substring", "footers_signing_key_42abc", "exact 'foo' would gut tokens containing foo"},
		{"short-x-run", "abcdXXXa123", "fewer than 8 consecutive X must not trip"},
		{"short-zero-run", "ab000000def", "fewer than 10 consecutive 0 must not trip"},
		{"long-real-token", "AKIA5VHJ7Q3GXKZM2BLN", "random alnum 20 chars — the AWS shape"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if IsPlaceholder([]byte(tc.raw)) {
				t.Fatalf("real-looking value %q (%s) was wrongly classified placeholder", tc.raw, tc.why)
			}
		})
	}
}

func TestIsPlaceholder_EmptyRaw(t *testing.T) {
	if IsPlaceholder(nil) {
		t.Fatal("nil raw must not be classified placeholder")
	}
	if IsPlaceholder([]byte{}) {
		t.Fatal("empty raw must not be classified placeholder")
	}
}

func TestPlaceholderSink_DropsAndCounts(t *testing.T) {
	rec := &recordingSink{}
	s := NewPlaceholderFilter(rec)

	mk := func(raw string) Finding {
		return Finding{
			Detector: detectors.AWS,
			Result:   detectors.Result{Raw: []byte(raw)},
			Chunk: &sources.Chunk{
				SourceType: sources.SourceFilesystem,
				SourceMetadata: sources.Metadata{
					Filesystem: &sources.FilesystemMeta{Path: "/a.txt", Line: 1},
				},
			},
		}
	}
	s.Emit(mk("AKIAIOSFODNN7EXAMPLE")) // placeholder — drop
	s.Emit(mk("AKIA5VHJ7Q3GXKZM2BLN")) // real — keep
	s.Emit(mk("YOUR_TOKEN_HERE"))      // placeholder — drop
	s.Emit(mk("XXXXXXXXXXXXXXXX"))     // placeholder — drop

	if got := len(rec.findings); got != 1 {
		t.Fatalf("want 1 forwarded (only the real token); got %d", got)
	}
	if string(rec.findings[0].Result.Raw) != "AKIA5VHJ7Q3GXKZM2BLN" {
		t.Fatalf("unexpected survivor: %q", rec.findings[0].Result.Raw)
	}
	if n := PlaceholderSuppressedCounter(s); n != 3 {
		t.Fatalf("suppressed count: got %d want 3", n)
	}
}

func TestPlaceholderSuppressedCounter_NotAPlaceholderSink(t *testing.T) {
	rec := &recordingSink{}
	if got := PlaceholderSuppressedCounter(rec); got != -1 {
		t.Fatalf("non-placeholder sink should report -1; got %d", got)
	}
}

func TestPlaceholderSink_CloseDelegates(t *testing.T) {
	rec := &recordingSink{}
	s := NewPlaceholderFilter(rec)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !rec.closed.Load() {
		t.Errorf("inner.Close not called through placeholder filter")
	}
}
