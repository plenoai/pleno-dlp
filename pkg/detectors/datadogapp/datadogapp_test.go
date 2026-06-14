//go:build detector_unit

package datadogapp

import (
	"context"
	"testing"
)

// High-entropy 40-hex tokens shaped like real Datadog Application keys.
const dummyApp = "0123456789abcdef0123456789abcdef01234567"
const dummyApp2 = "fedcba9876543210fedcba9876543210fedcba98"
const dummyAPI = "abcdef0123456789abcdef0123456789"

// A real SHA-1 (git empty-tree) used as a noise token in FP fixtures.
const sha1Noise = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

func TestFromData_StandaloneApp_HeaderForm(t *testing.T) {
	body := "DD-APPLICATION-KEY: " + dummyApp
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyApp {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_StandaloneApp_AssignmentForm(t *testing.T) {
	body := `DD_APP_KEY="` + dummyApp2 + `"`
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyApp2 {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("sha1="+dummyApp))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_SkipPaired(t *testing.T) {
	// When a 32-hex API key sits adjacent, the `datadog` detector owns this;
	// datadogapp must not also fire.
	body := "DD_API_KEY=" + dummyAPI + "\nDD_APPLICATION_KEY=" + dummyApp
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 (paired path delegates to datadog), got %d", len(res))
	}
}

// --- False-positive fixtures that the hardening now SUPPRESSES ---

// FP1: a real SHA-1 sits within 256 bytes of a DD_APP_KEY doc comment but is
// NOT in the assignment/header form. Anchoring kills it.
func TestFromData_FP_CommitShaNearKeyword(t *testing.T) {
	body := "# DD_APP_KEY is injected at deploy; pinned at commit " + sha1Noise + " (a real SHA-1 within 256 bytes of the keyword)"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("FP: commit SHA near DD_APP_KEY keyword should be suppressed, got %d", len(res))
	}
}

// FP2: an action-pin SHA near a DD_APPLICATION_KEY doc comment.
func TestFromData_FP_ActionPinSha(t *testing.T) {
	body := "steps:\n  - uses: actions/checkout@2541b1294d2704b0964813337f33b291d3f8596b  # near DD_APPLICATION_KEY doc comment"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("FP: action-pin SHA near keyword should be suppressed, got %d", len(res))
	}
}

// FP3: keyword is present, but the value is a vault placeholder and the only
// 40-hex on the chunk is an explicit `sha1:` checksum on another line.
func TestFromData_FP_VaultPlaceholderWithSha1Checksum(t *testing.T) {
	body := "DD_APPLICATION_KEY=\"<set-in-vault>\"\n# integrity sha1: " + sha1Noise
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("FP: sha1 checksum line should be suppressed, got %d", len(res))
	}
}

// FP4: low-entropy templated filler in the assignment form is dropped by the
// entropy floor even though the anchor matches.
func TestFromData_FP_LowEntropyPlaceholder(t *testing.T) {
	body := "DD_APP_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("FP: low-entropy repeated-nibble filler should be suppressed, got %d", len(res))
	}
	body0 := "DD_APP_KEY=0000000000000000000000000000000000000000"
	res0, _ := Scanner{}.FromData(context.Background(), false, []byte(body0))
	if len(res0) != 0 {
		t.Fatalf("FP: all-zero placeholder should be suppressed, got %d", len(res0))
	}
}

// TP: a real-shaped Application key in the assignment form is still detected
// even when an unrelated SHA-1 checksum sits on a nearby line.
func TestFromData_TP_StillDetectedDespiteNearbySha(t *testing.T) {
	body := "DD_APPLICATION_KEY=" + dummyApp2 + "\n# integrity sha1: " + sha1Noise
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("TP: real app key in assignment form should still be detected, got %d", len(res))
	}
	if string(res[0].Raw) != dummyApp2 {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}
