//go:build detector_unit

package crispchat

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// realKey is a Crisp plugin key shape: 64-char lowercase-hex, high entropy.
const realKey = "8f3c9a1b2e7d6c5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.CrispChat {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

// TestFromData_TruePositives: realistic key assignments STILL detected.
func TestFromData_TruePositives(t *testing.T) {
	cases := map[string][]byte{
		"env":      []byte("CRISP_API_KEY=" + realKey),
		"config":   []byte(`{"crisp_token": "` + realKey + `"}`),
		"ini-dash": []byte("crisp-key = " + realKey),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, body)
			if len(res) == 0 {
				t.Fatalf("expected >=1 true positive, got 0")
			}
			if string(res[0].Raw) != realKey {
				t.Fatalf("unexpected raw: %s", res[0].Raw)
			}
		})
	}
}

// TestFromData_FalsePositivesSuppressed: the dominant FP shapes near a Crisp
// embed must no longer arm a result.
func TestFromData_FalsePositivesSuppressed(t *testing.T) {
	cases := map[string][]byte{
		// FP1: SRI integrity hash on the Crisp widget <script> tag. base64,
		// integrity= marker, client.crisp.chat URL all in the vicinity.
		"sri_integrity": []byte(`<script src="https://client.crisp.chat/l.js" ` +
			`integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6R9GqQ8Kuxy9rx7HNQlGYl1kPzQho1wx4JwY8wCa"></script>`),
		// FP2: webpack/asset content hash near a "crisp integration" comment —
		// no assignment-style keyword precedes the hash within 48 bytes.
		"webpack_hash": []byte("// crisp integration\n" +
			"import './chunk-vendors.4f3c9a1b2e7d6c5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d.js'"),
		// FP3: an unrelated provider's token in the same .env block. The Crisp
		// reference is far from the foreign token and is not an assignment of it.
		"foreign_token": []byte("CRISP_WEBSITE_ID=8c1f0a2b\n" +
			"# padding padding padding padding padding padding padding\n" +
			"SOME_OTHER_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdef0123456789ab"),
		// FP4: low-entropy lowercase-hex run that clears the length floor but
		// is not a random key, even with a Crisp assignment keyword.
		"low_entropy": []byte("crisp_api_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, body)
			if len(res) != 0 {
				t.Fatalf("expected FP suppression, got %d result(s): %q", len(res), res[0].Raw)
			}
		})
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("token=" + realKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without crisp assignment, got %d", len(res))
	}
}

func TestFromData_Dedup(t *testing.T) {
	body := []byte("crisp_key=" + realKey + "\ncrisp_token=" + realKey)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	if got := redact(realKey); got != "8f3c9a1b..." {
		t.Fatalf("unexpected redact: %s", got)
	}
}
