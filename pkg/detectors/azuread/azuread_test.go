package azuread

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummySecret = "AbC8Q~aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ab"
const dummyAppID = "01234567-89ab-cdef-0123-456789abcdef"
const dummyTenantID = "aabbccdd-1122-3344-5566-778899aabbcc"

func TestFromData_Positive_PairsAppID(t *testing.T) {
	body := []byte("AZURE_CLIENT_ID=" + dummyAppID + "\nAZURE_CLIENT_SECRET=" + dummySecret)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummySecret {
		t.Fatalf("Raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummyAppID {
		t.Fatalf("RawV2 mismatch: %q", res[0].RawV2)
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %v", res[0].Severity)
	}
	if res[0].Verified {
		t.Fatal("should not be verified without verify=true")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("X=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_Negative_NoTilde(t *testing.T) {
	body := []byte("AZURE_CLIENT_SECRET=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without tilde, got %d", len(res))
	}
}

// TestFromData_HardeningTable asserts the semantic_harden FP controls: the
// tilde+vicinity gate alone used to pass low-entropy fillers and hyphenated
// human-readable slugs that sit near the word "azure". Each suppressed case
// below carries a tilde and an azure keyword in the window, so only the
// entropy / mono-class / separator gates can reject them.
func TestFromData_HardeningTable(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		detect bool
	}{
		{
			// FP: tilde-prefixed username/dir token, 30+ alnum, next to "azure",
			// no entropy or mono-class guard previously. Suppressed by the
			// separator-density cap (4 dashes in the trailing run).
			name:   "fp_tilde_username_dir_slug",
			body:   "AZURE_NOTE=workdir is ~azureuser-build-artifacts-staging-001122",
			detect: false,
		},
		{
			// FP: low-entropy filler/template value with a tilde. Passes the
			// tilde+vicinity gate but is mono-class (no digit) and low entropy.
			name:   "fp_low_entropy_placeholder",
			body:   "azure_placeholder=PLACEHOLDER~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			detect: false,
		},
		{
			// FP: hyphenated human-readable slug containing a tilde near an
			// azure keyword. Suppressed by the separator-density cap (5 dashes).
			name:   "fp_hyphenated_slug",
			body:   "# azure migration ticket ABC~feature-flag-rollout-phase-two-canary-2026",
			detect: false,
		},
		{
			// TP: a real-shaped Azure client secret still detected.
			name:   "tp_real_shaped_secret",
			body:   "AZURE_CLIENT_SECRET=" + dummySecret,
			detect: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := Scanner{}.FromData(context.Background(), false, []byte(c.body))
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			got := len(res) > 0
			if got != c.detect {
				t.Fatalf("detect=%v want %v (results=%d) for body %q", got, c.detect, len(res), c.body)
			}
		})
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummySecret)
	if r == dummySecret {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "AbC8Q~") {
		t.Fatalf("missing prefix: %q", r)
	}
}

// TestFromData_ContextExtractTenantEnv verifies tenant_id extraction from a
// realistic .env chunk where AZURE_TENANT_ID sits near the secret.
func TestFromData_ContextExtractTenantEnv(t *testing.T) {
	chunk := "AZURE_TENANT_ID=" + dummyTenantID + "\n" +
		"AZURE_CLIENT_ID=" + dummyAppID + "\n" +
		"AZURE_CLIENT_SECRET=" + dummySecret + "\n"
	res, err := Scanner{}.FromData(context.Background(), false, []byte(chunk))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	tid, ok := res[0].ExtraData["tenant_id"]
	if !ok {
		t.Fatal("tenant_id not found in ExtraData")
	}
	if tid != dummyTenantID {
		t.Fatalf("tenant_id mismatch: got %q, want %q", tid, dummyTenantID)
	}
	cid, ok := res[0].ExtraData["client_id"]
	if !ok {
		t.Fatal("client_id not found in ExtraData")
	}
	if cid != dummyAppID {
		t.Fatalf("client_id mismatch: got %q, want %q", cid, dummyAppID)
	}
}

// TestFromData_ContextExtractTenantJSON verifies tenant_id extraction from a
// realistic JSON config chunk.
func TestFromData_ContextExtractTenantJSON(t *testing.T) {
	chunk := `{
  "azure": {
    "tenant_id": "` + dummyTenantID + `",
    "client_id": "` + dummyAppID + `",
    "client_secret": "` + dummySecret + `"
  }
}`
	res, err := Scanner{}.FromData(context.Background(), false, []byte(chunk))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	tid, ok := res[0].ExtraData["tenant_id"]
	if !ok {
		t.Fatal("tenant_id not found in ExtraData")
	}
	if tid != dummyTenantID {
		t.Fatalf("tenant_id mismatch: got %q, want %q", tid, dummyTenantID)
	}
}

// TestFromData_VerifySkippedWhenNoTenant asserts that when verify=true but no
// tenant_id is in the chunk, verification is skipped and the reason is recorded.
func TestFromData_VerifySkippedWhenNoTenant(t *testing.T) {
	chunk := "AZURE_CLIENT_ID=" + dummyAppID + "\n" +
		"AZURE_CLIENT_SECRET=" + dummySecret + "\n"
	res, err := Scanner{}.FromData(context.Background(), true, []byte(chunk))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("should not be verified without tenant_id in context")
	}
	reason, ok := res[0].ExtraData["verify_skip_reason"]
	if !ok {
		t.Fatal("verify_skip_reason not found in ExtraData")
	}
	if reason != "tenant_id_not_in_context" {
		t.Fatalf("unexpected verify_skip_reason: %q", reason)
	}
}

// TestVerify_PackedFormat asserts the Verify method correctly parses the
// packed "tenant_id:client_id:client_secret" format.
func TestVerify_PackedFormat(t *testing.T) {
	t.Run("invalid_format_too_few_parts", func(t *testing.T) {
		_, err := Scanner{}.Verify(context.Background(), "only_one_part")
		if err == nil {
			t.Fatal("expected error for invalid packed format")
		}
		if !strings.Contains(err.Error(), "expected packed format") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid_format_two_parts", func(t *testing.T) {
		_, err := Scanner{}.Verify(context.Background(), "tenant:client")
		if err == nil {
			t.Fatal("expected error for invalid packed format")
		}
	})

	t.Run("valid_three_parts_parses_ok", func(t *testing.T) {
		// The actual HTTP call will fail (no server), but parsing should succeed.
		// verifyOAuth2 returns (false, nil) on connection failure.
		ok, err := Scanner{}.Verify(context.Background(), dummyTenantID+":"+dummyAppID+":"+dummySecret)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Not verified because there's no real Azure AD endpoint to hit.
		if ok {
			t.Fatal("should not be verified against a non-existent endpoint")
		}
	})
}
