package droneci

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a mixed-case, high-entropy 24-char alnum string shaped like a
// real Drone PAT. Not a real token.
const dummy = "AbCdEf0123456789AbGhIj01"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.DroneCI {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

// TestFromData_Positive: a token bound to a drone-prefixed assignment
// anchor is still detected.
func TestFromData_Positive(t *testing.T) {
	cases := []string{
		"DRONE_TOKEN=" + dummy,
		"drone_token: " + dummy,
		`drone-secret = "` + dummy + `"`,
		"DRONE_SERVER_TOKEN: " + dummy,
	}
	for _, body := range cases {
		res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
		if err != nil {
			t.Fatalf("%q: err: %v", body, err)
		}
		if len(res) < 1 {
			t.Fatalf("%q: expected >=1, got %d", body, len(res))
		}
		if string(res[0].Raw) != dummy {
			t.Fatalf("%q: raw mismatch: %q", body, res[0].Raw)
		}
	}
}

// TestFromData_SuppressesUnanchoredKeyword: a token that merely sits near
// the bare word "drone" (no drone-prefixed assignment) is no longer a hit.
func TestFromData_SuppressesUnanchoredKeyword(t *testing.T) {
	// base62 object id near a comment mentioning drone.io
	body := []byte("# see drone.io docs\nobject_id = 0Oj4kFhT2mXbQv8sZc1Rd6Yp")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (no drone assignment anchor), got %d", len(res))
	}
}

// TestFromData_SuppressesForeignProviderKey: another provider's key in the
// same .drone.yml env block must not be attributed to Drone.
func TestFromData_SuppressesForeignProviderKey(t *testing.T) {
	body := []byte(`# .drone.yml
environment:
  DRONE_SERVER: https://drone.example.com
  SEGMENT_WRITE_KEY: Xk29Lm03Pq84Rt61Vw57Zb40`)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (foreign-provider key, not drone-anchored), got %d", len(res))
	}
}

// TestFromData_SuppressesHexCommitSha: a hex build/commit identifier
// assigned to a drone-prefixed key is rejected by the pure-hex exclusion.
func TestFromData_SuppressesHexCommitSha(t *testing.T) {
	body := []byte("DRONE_COMMIT_SHA=a1b2c3d4e5f6a7b8c9d0e1f2")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (pure-hex commit sha), got %d", len(res))
	}
}

// TestFromData_SuppressesLowEntropy: a repeated-char string assigned to a
// drone key is dropped by the entropy / all-same-char gate.
func TestFromData_SuppressesLowEntropy(t *testing.T) {
	body := []byte("DRONE_TOKEN=AAAAAAAAAAAAAAAAAAAAAAAA")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy lookalike), got %d", len(res))
	}
}

func TestFromData_DedupesIdenticalTokens(t *testing.T) {
	body := []byte("DRONE_TOKEN=" + dummy + "\ndrone_secret=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected dedup to 1 result, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "AbCdEf01") {
		t.Fatalf("missing prefix: %q", r)
	}
}
