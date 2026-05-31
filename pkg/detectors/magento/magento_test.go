package magento

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// realShape is a 32-char [a-z0-9] token that uses letters outside the
// hex alphabet [g-z] and has healthy entropy — the shape of a real
// Magento admin/integration access token.
const realShape = "z9k3qw7mxv2p5r8tn4hj6cgyd1blf0su"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Magento {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

// TestFromData_TruePositive: a real-shaped token in a credential
// assignment next to the magento keyword is still detected.
func TestFromData_TruePositive(t *testing.T) {
	body := []byte("MAGENTO_ADMIN_TOKEN=" + realShape)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if string(res[0].Raw) != realShape {
		t.Fatalf("wrong raw: %q", res[0].Raw)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED_TOKEN=" + realShape)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_SuppressesHexDigest: an MD5 cache-key hex digest sitting
// inside a Magento log line (literal "magento" within 128B) must NOT be
// reported — it is pure [a-f0-9] and carries no credential.
func TestFromData_SuppressesHexDigest(t *testing.T) {
	body := []byte("magento.CRITICAL: cache hash d41d8cd98f00b204e9800998ecf8427e written")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (hex digest suppressed), got %d", len(res))
	}
}

// TestFromData_SuppressesFormKeyHex: a Magento form/cache key (32 hex
// chars) near the magento keyword must be suppressed by the hex-letter
// exclusion.
func TestFromData_SuppressesFormKeyHex(t *testing.T) {
	body := []byte("Magento cache key 1a79a4d60de6718e8e5b326e338ae533 stored")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (form-key hex suppressed), got %d", len(res))
	}
}

// TestFromData_SuppressesGitHashLikeNoContext: a lowercased commit-hash
// lookalike near a magento module path but with no credential-context
// term must be suppressed.
func TestFromData_SuppressesNoCredentialContext(t *testing.T) {
	// realShape passes the hex/entropy gates and "magento" is present,
	// but there is no credential-context term within the tight window.
	body := []byte("vendor/magento/module-foo build artifact " + realShape + " bundled")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (no credential context), got %d", len(res))
	}
}
