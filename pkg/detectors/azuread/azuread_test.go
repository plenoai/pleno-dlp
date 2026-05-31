package azuread

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummySecret = "AbC8Q~aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789ab"
const dummyAppID = "01234567-89ab-cdef-0123-456789abcdef"

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
		t.Fatal("AzureAD is unverified-by-design (tenant unknown)")
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
