package detectors

import "testing"

func TestTokenChecksum(t *testing.T) {
	body30 := "Zq8Lm3XcVb7Nn2Kk5Jh4Gf6Dd9Ss1A"
	valid := body30 + CRC32Base62(body30)
	if got := TokenChecksum(valid); got != "valid" {
		t.Fatalf("valid body: got %q", got)
	}
	bad := []byte(valid)
	bad[35] ^= 1
	if got := TokenChecksum(string(bad)); got != "invalid" {
		t.Fatalf("tampered body: got %q", got)
	}
	if got := TokenChecksum("short"); got != "" {
		t.Fatalf("short body: got %q", got)
	}
	if got := CRC32Base62(""); got != "000000" {
		t.Fatalf("crc32(\"\") = 0 must pad to 000000, got %q", got)
	}
}
