package detectors

import (
	"errors"
	"testing"
)

// TestResult_Verdict pins the three-valued derivation issue #246 depends on:
// a failed verification attempt (VerificationErr set, Verified false) must
// classify as Indeterminate, distinct from a provider that affirmatively
// said "not live" (Verified false, no error).
func TestResult_Verdict(t *testing.T) {
	tests := []struct {
		name        string
		result      Result
		wantVerdict Verdict
	}{
		{"verified", Result{Verified: true}, VerdictVerified},
		{"unverified", Result{Verified: false}, VerdictUnverified},
		{"indeterminate", Result{Verified: false, VerificationErr: errors.New("dial tcp: i/o timeout")}, VerdictIndeterminate},
		// Verified takes priority even if a stale error were somehow left
		// set — a detector reporting the secret live is unambiguous.
		{"verified wins over stray error", Result{Verified: true, VerificationErr: errors.New("stale")}, VerdictVerified},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.result.Verdict(); got != tc.wantVerdict {
				t.Errorf("Verdict() = %v, want %v", got, tc.wantVerdict)
			}
		})
	}
}

func TestVerdict_String(t *testing.T) {
	tests := []struct {
		v    Verdict
		want string
	}{
		{VerdictVerified, "verified"},
		{VerdictUnverified, "unverified"},
		{VerdictIndeterminate, "indeterminate"},
	}
	for _, tc := range tests {
		if got := tc.v.String(); got != tc.want {
			t.Errorf("%d.String() = %q, want %q", tc.v, got, tc.want)
		}
	}
}

// TestDefaultSeverityForVerdict pins the severity-mapping decision for
// issue #246: Indeterminate maps to the same severity as Verified
// (Critical) rather than falling back to the Unverified per-type table.
// Rationale: a failed verification attempt doesn't disprove liveness, so
// treating it as less severe than a live credential is the wrong failure
// mode for a secrets scanner to fail into.
func TestDefaultSeverityForVerdict(t *testing.T) {
	tests := []struct {
		name    string
		t       DetectorType
		verdict Verdict
		want    Severity
	}{
		{"verified AWS", AWS, VerdictVerified, SeverityCritical},
		{"indeterminate AWS", AWS, VerdictIndeterminate, SeverityCritical},
		{"unverified AWS falls back to explicit-detector default", AWS, VerdictUnverified, SeverityHigh},
		{"unverified GenericHighEntropy falls back to its own default", GenericHighEntropy, VerdictUnverified, SeverityMedium},
		{"indeterminate GenericHighEntropy still escalates to Critical", GenericHighEntropy, VerdictIndeterminate, SeverityCritical},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DefaultSeverityForVerdict(tc.t, tc.verdict); got != tc.want {
				t.Errorf("DefaultSeverityForVerdict(%v, %v) = %v, want %v", tc.t, tc.verdict, got, tc.want)
			}
		})
	}
}
