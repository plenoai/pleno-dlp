package cloudflarer2

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const (
	// Entropy-clean 16-symbol-balanced hex (each nibble appears, no long
	// repeats / no monotone sequence) so it clears the minHexEntropy floor.
	dummyID     = "0123456789abcdef0123456789abcdef"
	dummySecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.CloudflareR2 {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("# r2_access_key\nR2_ACCESS_KEY_ID=" + dummyID + "\nR2_SECRET=" + dummySecret)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("RawV2 mismatch: %q", string(res[0].RawV2))
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("expected SeverityCritical, got %v", res[0].Severity)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("X=" + dummyID + "\nY=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without R2 keyword, got %d", len(res))
	}
}

func TestFromData_MissingSecret(t *testing.T) {
	body := []byte("# r2_access_key id only\nR2_ACCESS_KEY_ID=" + dummyID)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without companion secret, got %d", len(res))
	}
}

// TestFromData_FalsePositives_Suppressed exercises the digest-lookalike
// corpus described in the harden plan: files that mention R2 but also carry
// content hashes / git SHAs / lockfile integrity digests / ETags within the
// vicinity. None of these may be emitted as an R2 id+secret pair.
func TestFromData_FalsePositives_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			// README: a SHA-256 (64 hex) pairs with an MD5 (32 hex) inside the
			// R2 keyword span. Digest-context words ("sha256", "md5") around the
			// 32-hex id must reject it.
			name: "readme_sha256_plus_md5_near_r2_keyword",
			body: "cloudflare_r2 bucket; build artifact sha256: " +
				dummySecret + " (md5 short-ref " + dummyID + " nearby)",
		},
		{
			// Lockfile/SBOM fragment near an r2_endpoint comment: an ETag-like
			// 32-hex and a 64-hex hash co-occur, surrounded by integrity / etag /
			// commit context.
			name: "lockfile_integrity_etag_commit_near_r2_endpoint",
			body: "# r2_endpoint=...\nresolved#commit " + dummyID +
				"\nintegrity sha512-... etag \"" + dummyID + "\" hash " + dummySecret,
		},
		{
			// All-zero placeholder hex inside an otherwise valid R2 config line.
			// The entropy floor must drop it even though the keyword is adjacent.
			name: "zero_placeholder_below_entropy_floor",
			body: "R2_ACCESS_KEY_ID=00000000000000000000000000000000\n" +
				"r2_secret=0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Scanner{}.FromData(context.Background(), false, []byte(tc.body))
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if len(res) != 0 {
				t.Fatalf("expected 0 results (suppressed FP), got %d", len(res))
			}
		})
	}
}

// TestFromData_TruePositive_StillDetected confirms a realistic R2 credential
// block survives all gates: keyword adjacency, entropy floor, no digest
// context.
func TestFromData_TruePositive_StillDetected(t *testing.T) {
	body := []byte("# Cloudflare R2 credentials\n" +
		"R2_ACCESS_KEY_ID=" + dummyID + "\n" +
		"R2_SECRET_ACCESS_KEY=" + dummySecret + "\n")
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 (true positive still detected), got %d", len(res))
	}
	if string(res[0].Raw) != dummyID {
		t.Fatalf("Raw mismatch: %q", string(res[0].Raw))
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("RawV2 mismatch: %q", string(res[0].RawV2))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "01234567") {
		t.Fatalf("missing prefix: %q", r)
	}
}
