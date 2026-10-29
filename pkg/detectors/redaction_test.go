package detectors

import (
	"strings"
	"testing"
)

func TestSafeRedactedPreservesSafeCandidate(t *testing.T) {
	got := SafeRedacted("AKIA12...", []byte("AKIAIOSFODNN7EXAMPLE"), nil)
	if got != "AKIA12..." {
		t.Fatalf("safe candidate changed: got %q", got)
	}
}

func TestSafeRedactedMasksCompleteRawAndRawV2(t *testing.T) {
	for _, tc := range []struct {
		name      string
		candidate string
		raw       string
		rawV2     string
	}{
		{name: "short raw", candidate: "p4ss", raw: "p4ss"},
		{name: "raw v2 inside candidate", candidate: "account-id", raw: "long credential", rawV2: "id"},
		{name: "raw v2 as candidate", candidate: "client-secret", raw: "client", rawV2: "client-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := SafeRedacted(tc.candidate, []byte(tc.raw), []byte(tc.rawV2))
			if containsSecret(got, []byte(tc.raw)) || containsSecret(got, []byte(tc.rawV2)) {
				t.Fatalf("display %q contains Raw=%q or RawV2=%q", got, tc.raw, tc.rawV2)
			}
		})
	}
}

func TestRedactShortSecretUsesSafeMarker(t *testing.T) {
	for _, secret := range []string{"p4ss", "***", "..."} {
		got := Redact([]byte(secret), nil)
		if got == "" || strings.Contains(got, secret) {
			t.Errorf("Redact(%q) = %q, want a nonempty display that excludes the secret", secret, got)
		}
	}
}

func TestRedactSelectsMarkerThatDoesNotMatchEitherSecret(t *testing.T) {
	raw := []byte("***")
	rawV2 := []byte("...")
	got := safeMarker(raw, rawV2)
	if containsSecret(got, raw) || containsSecret(got, rawV2) {
		t.Fatalf("safeMarker returned %q containing Raw or RawV2", got)
	}
}
