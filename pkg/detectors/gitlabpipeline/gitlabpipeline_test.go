//go:build detector_unit

package gitlabpipeline

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// A realistic, high-entropy 40-hex trigger token (not a sequential/patterned
// placeholder). Entropy well above the 3.0 bits/char gate.
const realToken = "4f9c1a7e2b8d6035f1ce94a70d23bf86e5470c19"

// A realistic UUID-shaped trigger token (newer GitLab format).
const realUUID = "8f14e45f-ceea-467d-9b3a-1a2b3c4d5e6f"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.GitLabPipeline {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

// TRUE POSITIVE: assignment-form trigger token is still detected.
func TestFromData_Positive_HexAssignment(t *testing.T) {
	body := []byte("CI_PIPELINE_TRIGGER=" + realToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != realToken {
		t.Fatalf("raw mismatch: %s", res[0].Raw)
	}
}

// TRUE POSITIVE: UUID-shaped trigger token assigned to trigger_token key.
func TestFromData_Positive_UUIDAssignment(t *testing.T) {
	body := []byte(`trigger_token = "` + realUUID + `"`)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

// FALSE POSITIVE (suppressed): a Git commit SHA mentioned near the keyword but
// NOT in assignment form, plus a commit-context word in vicinity.
func TestFromData_FP_GitCommitSHA(t *testing.T) {
	body := []byte("# pipeline_trigger fires on commit " + realToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected commit SHA to be suppressed, got %d", len(res))
	}
}

// FALSE POSITIVE (suppressed): an unrelated UUID resource id co-located in the
// same block as a trigger_token key that holds a *different* value. The loose
// 256-byte vicinity used to match the wrong UUID; the assignment anchor binds
// trigger_token only to var.secret, so the resource UUID is dropped.
func TestFromData_FP_UnrelatedUUIDInBlock(t *testing.T) {
	body := []byte(`resource "x" {
  id            = "550e8400-e29b-41d4-a716-446655440000"
  trigger_token = var.secret
}`)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected unrelated UUID to be suppressed, got %d", len(res))
	}
}

// FALSE POSITIVE (suppressed): low-entropy / patterned hex placeholder even in
// assignment form is dropped by the entropy gate.
func TestFromData_FP_LowEntropyPlaceholder(t *testing.T) {
	body := []byte("trigger_token=0000000000000000000000000000000000000000")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected low-entropy placeholder to be suppressed, got %d", len(res))
	}
}

// A bare token with no trigger keyword in assignment form must not match.
func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("X="+realToken))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("pipeline_trigger=" + realToken + "\npipeline_trigger=" + realToken)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(realToken)
	if r == realToken {
		t.Fatal("redact didn't redact")
	}
}
