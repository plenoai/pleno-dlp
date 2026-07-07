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
		{"aws-docs-example-key-id", "AKIAIOSFODNN7EXAMPLE", "AWS SDK docs' canonical example access key id — exact-literal match, not a substring heuristic"},
		{"aws-docs-example-secret", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AWS SDK docs' canonical example secret key — exact-literal match"},
		{"your-token-here", "YOUR_TOKEN_HERE", "templated placeholder — substring YOUR_TOKEN"},
		{"your-key", "YOUR_KEY", "templated placeholder — substring YOUR_KEY"},
		{"your-secret", "YOUR_SECRET", "templated placeholder — substring YOUR_SECRET"},
		{"angle-token", "<TOKEN>", "bracket-style placeholder"},
		{"angle-secret", "<SECRET>", "bracket-style placeholder"},
		{"angle-key", "<KEY>", "bracket-style placeholder"},
		{"placeholder-exact", "PLACEHOLDER", "word marker is 100% of the value"},
		{"redacted-exact", "REDACTED", "word marker is 100% of the value"},
		{"example-exact", "Example", "word marker is 100% of the value"},
		{"example-key-majority", "EXAMPLE_KEY", "word marker (7/10 alnum bytes) is a strict majority"},
		{"placeholder-token-majority", "PLACEHOLDER_TOKEN", "word marker (11/16 alnum bytes) is a strict majority"},
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

		// --- issue #290 regression corpus: real-shaped secrets whose
		// value merely CONTAINS a word marker as a substring/fragment
		// must survive — this is exactly the class of finding the old
		// bytes.Contains check silently dropped. ---
		{"filezilla-real-password", "ExamplePas123", "PR #289's FileZillaXML fixture: a real <Pass> value that happens to start with the fragment \"Example\" — was silently dropped pre-#290"},
		{"scoped-key-with-example-fragment", "your-api-key-EXAMPLE-us-east-1", "a real key scoped to example.com-named infra; 'example' is 7 of 24 alnum bytes, well under majority"},
		{"redacted-embedded-in-prose", "Bearer REDACTED here", "'redacted' is 8 of 18 alnum bytes (44%) — not a majority, so this no longer trips; a well-formed detector should not extract prose like this as Result.Raw in the first place, and if it does that is a detector-regex bug, not something the placeholder filter should paper over by treating the substring as authoritative (scope change from the pre-#290 substring rule — see PR body)"},
		{"redacted-fragment-in-token", "svc_9f8g7h6jredacted5k4l3m2n1", "'redacted' is a fragment inside one continuous alnum run, not a standalone word"},
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
	s := NewPlaceholderFilter(rec, nil)

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
	s.Emit(mk("AKIAIOSFODNN7EXAMPLE")) // placeholder — drop (known AWS docs literal)
	s.Emit(mk("AKIA5VHJ7Q3GXKZM2BLN")) // real — keep
	s.Emit(mk("YOUR_TOKEN_HERE"))      // placeholder — drop
	s.Emit(mk("XXXXXXXXXXXXXXXX"))     // placeholder — drop
	s.Emit(mk("ExamplePas123"))        // real (issue #290) — keep

	if got := len(rec.findings); got != 2 {
		t.Fatalf("want 2 forwarded (the real token + the real-shaped FileZilla-style password); got %d", got)
	}
	got := map[string]bool{}
	for _, f := range rec.findings {
		got[string(f.Result.Raw)] = true
	}
	for _, want := range []string{"AKIA5VHJ7Q3GXKZM2BLN", "ExamplePas123"} {
		if !got[want] {
			t.Errorf("expected %q to survive, forwarded set: %v", want, got)
		}
	}
	if n := PlaceholderSuppressedCounter(s); n != 3 {
		t.Fatalf("suppressed count: got %d want 3", n)
	}
}

// TestPlaceholderSink_AuditForwardsSuppressed pins the --show-suppressed
// mechanism (issue #290): when an audit sink is wired in, a suppressed
// finding is tagged SuppressedBy="placeholder" and forwarded to audit
// instead of only being tallied — but it must never reach inner, so it
// stays out of dedup / counting / --fail-on.
func TestPlaceholderSink_AuditForwardsSuppressed(t *testing.T) {
	inner := &recordingSink{}
	audit := &recordingSink{}
	s := NewPlaceholderFilter(inner, audit)

	mk := func(raw string) Finding {
		return Finding{
			Detector: detectors.AWS,
			Result:   detectors.Result{Raw: []byte(raw)},
		}
	}
	s.Emit(mk("AKIAIOSFODNN7EXAMPLE")) // placeholder — audited, not forwarded to inner
	s.Emit(mk("AKIA5VHJ7Q3GXKZM2BLN")) // real — forwarded to inner, not audited

	if len(inner.findings) != 1 || string(inner.findings[0].Result.Raw) != "AKIA5VHJ7Q3GXKZM2BLN" {
		t.Fatalf("inner should see only the real finding, got %+v", inner.findings)
	}
	if inner.findings[0].SuppressedBy != "" {
		t.Errorf("a normally-forwarded finding must not carry SuppressedBy, got %q", inner.findings[0].SuppressedBy)
	}
	if len(audit.findings) != 1 || string(audit.findings[0].Result.Raw) != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("audit should see only the suppressed finding, got %+v", audit.findings)
	}
	if got := audit.findings[0].SuppressedBy; got != "placeholder" {
		t.Errorf("SuppressedBy = %q, want %q", got, "placeholder")
	}
	if n := PlaceholderSuppressedCounter(s); n != 1 {
		t.Fatalf("suppressed count: got %d want 1", n)
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
	s := NewPlaceholderFilter(rec, nil)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !rec.closed.Load() {
		t.Errorf("inner.Close not called through placeholder filter")
	}
}
