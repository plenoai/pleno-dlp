package engine

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// TestIrregularCoverage_PercentSecretAwayFromWindowEdges protects the
// decoder/engine seam for a percent-encoded value in a large run. A window
// that starts or ends inside a %XX escape is still expected to recover a
// complete credential in its interior; rejecting the whole window loses real
// configuration data when the value is not near a neighboring window.
func TestIrregularCoverage_PercentSecretAwayFromWindowEdges(t *testing.T) {
	const token = "AKIAIOSFODNN7EXAMPLE"
	plain := make([]byte, 0, 60_000)
	plain = append(plain, []byte("comment=")...)
	plain = append(plain, bytes.Repeat([]byte{'x'}, 26_666)...)
	plain = append(plain, []byte("&key="+token+"&tail=")...)
	plain = append(plain, bytes.Repeat([]byte{'y'}, 20_000)...)

	encoded := make([]byte, 0, len(plain)*3)
	for _, b := range plain {
		encoded = append(encoded, fmt.Sprintf("%%%02X", b)...)
	}
	if len(encoded) < 96_256 {
		t.Fatalf("fixture too short to exercise an interior invalid window: %d", len(encoded))
	}

	if got := runIrregularEngine(t, token, encoded); got != 1 {
		t.Fatalf("percent-encoded token findings = %d, want 1", got)
	}
}

// TestIrregularCoverage_Base64SecretAwayFromWindowEdges protects the
// decoder/engine seam when a long Base64 run starts at each possible modulo-4
// offset. The token is in a later 32 KiB window, far from both its edges, so
// overlap cannot mask a window-local phase reset.
func TestIrregularCoverage_Base64SecretAwayFromWindowEdges(t *testing.T) {
	const token = "AKIAIOSFODNN7EXAMPLE"

	for prefixLen := 0; prefixLen <= 3; prefixLen++ {
		t.Run(fmt.Sprintf("prefix=%d", prefixLen), func(t *testing.T) {
			plain := make([]byte, 0, 80_000)
			plain = append(plain, bytes.Repeat([]byte{'x'}, 60_000)...)
			plain = append(plain, []byte(token)...)
			plain = append(plain, bytes.Repeat([]byte{'y'}, 20_000)...)

			encoded := make([]byte, prefixLen, prefixLen+base64.StdEncoding.EncodedLen(len(plain)))
			for i := range encoded {
				encoded[i] = '!'
			}
			encoded = append(encoded, base64.StdEncoding.EncodeToString(plain)...)
			if bytes.Contains(encoded, []byte(token)) {
				t.Fatal("fixture unexpectedly contains the plaintext token")
			}

			if got := runIrregularEngine(t, token, encoded); got != 1 {
				t.Fatalf("Base64 token findings = %d, want 1", got)
			}
		})
	}
}

// TestIrregularCoverage_HexSecretAwayFromWindowEdges protects an odd-offset
// uppercase hex run. Short delimiters put the token's hex digits at both even
// and odd absolute offsets; the token sits in a later window where
// independently decoding an even-length fragment can pair the wrong nibbles.
func TestIrregularCoverage_HexSecretAwayFromWindowEdges(t *testing.T) {
	const token = "AKIAIOSFODNN7EXAMPLE"
	for prefixLen := 0; prefixLen <= 3; prefixLen++ {
		t.Run(fmt.Sprintf("prefix=%d", prefixLen), func(t *testing.T) {
			plain := make([]byte, 0, 80_000)
			plain = append(plain, bytes.Repeat([]byte{'x'}, 60_000)...)
			plain = append(plain, []byte(token)...)
			plain = append(plain, bytes.Repeat([]byte{'y'}, 20_000)...)

			hexRun := bytes.ToUpper([]byte(hex.EncodeToString(plain)))
			encoded := make([]byte, prefixLen, prefixLen+hex.EncodedLen(len(plain)))
			for i := range encoded {
				encoded[i] = '!'
			}
			encoded = append(encoded, hexRun...)
			if bytes.Contains(encoded, []byte(token)) {
				t.Fatal("fixture unexpectedly contains the plaintext token")
			}
			if got := runIrregularEngine(t, token, encoded); got != 1 {
				t.Fatalf("uppercase hex token findings = %d, want 1", got)
			}
		})
	}
}

func runIrregularEngine(t *testing.T, token string, data []byte) int {
	t.Helper()
	sink := &engineRecordingSink{}
	eng := NewWithDetectors(
		[]detectors.Detector{fakeDetector{needle: token}},
		Options{Concurrency: 1, NoVerify: true},
		sink,
	)
	if err := eng.Run(context.Background(), fakeSource{data: data}); err != nil {
		t.Fatalf("engine.Run: %v", err)
	}
	return len(sink.Findings())
}
