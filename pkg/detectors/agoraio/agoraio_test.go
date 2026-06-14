//go:build detector_unit

package agoraio

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Realistic high-entropy 32-hex values (not sequential / uniform / MD5 of a
// well-known string). Distinct enough to pass the entropy + lookalike gates.
const (
	appID   = "9f4c1a7e2b8d05f361ac9e74d0b2f8a1"
	appCert = "3e7b91d4a06c2f85be17094d6af3c2b8"
	// MD5 of the empty string and of "a" — classic checksum lookalikes.
	md5empty = "d41d8cd98f00b204e9800998ecf8427e"
	md5a     = "0cc175b9c0f1b6a831c399e269772661"
)

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.AgoraIO {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

// True positive: an id-labelled hex and a cert-labelled hex on adjacent
// assignment lines still emit the id:cert pair.
func TestFromData_Found(t *testing.T) {
	body := []byte("AGORA_APP_ID=" + appID + " AGORA_APP_CERT=" + appCert)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 pair")
	}
	found := false
	for _, r := range res {
		if string(r.RawV2) == appID+":"+appCert {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected RawV2 %q, got %+v", appID+":"+appCert, res)
	}
}

// True positive variant: JSON-style appId / appCertificate keys.
func TestFromData_FoundJSON(t *testing.T) {
	body := []byte(`{"appId":"` + appID + `","appCertificate":"` + appCert + `"}`)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1 pair for JSON shape")
	}
}

// No agora-specific label anywhere → suppressed.
func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED " + appID + " " + appCert)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// FP suppressed: a changelog mentioning "Agora release" followed by two
// unrelated MD5 checksums. Old detector cross-paired the two MD5s; the
// tightened 40-byte vicinity + missing id/cert role now drops them.
func TestFromData_FP_ChangelogTwoMD5(t *testing.T) {
	body := []byte("Agora release notes for today. Build artifacts: " +
		md5empty + " and also " + md5a + " were published.")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (no id/cert labels), got %d: %+v", len(res), res)
	}
}

// FP suppressed: a lockfile/manifest entry near an `agora` module listing
// integrity hashes under md5/etag keys. The exclude-label gate drops both.
func TestFromData_FP_LockfileIntegrity(t *testing.T) {
	body := []byte(`"agora-sdk": { "md5": "` + md5a + `", "etag": "` + md5empty + `" }`)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (checksum context excluded), got %d: %+v", len(res), res)
	}
}

// FP suppressed: low-entropy / sequential hex near proper labels must not
// pass the entropy + uniform/sequential gates.
func TestFromData_FP_DegenerateHex(t *testing.T) {
	const allZero = "00000000000000000000000000000000"
	const seq = "0123456789abcdef0123456789abcdef"
	body := []byte("AGORA_APP_ID=" + allZero + " AGORA_APP_CERT=" + seq)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (degenerate hex), got %d: %+v", len(res), res)
	}
}
