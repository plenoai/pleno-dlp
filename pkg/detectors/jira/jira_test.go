package jira

import (
	"context"
	"strings"
	"testing"
)

// dummy is a realistic Atlassian base62 token shape: mixed-case + digits,
// not pure hex, high entropy.
const dummy = "ATATT3xFfGF0abcdEfgh1234"

func TestFromData_Positive(t *testing.T) {
	body := []byte("JIRA_API_TOKEN=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if res[0].Verified {
		t.Fatal("jira is unverified-by-design")
	}
}

// TruePositive_StillDetected: a lower-case assignment key with the genuine
// token shape remains detected after hardening.
func TestFromData_TruePositive_AssignmentVariant(t *testing.T) {
	body := []byte("config:\n  jira_token: " + dummy + "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 true-positive, got %d", len(res))
	}
}

func TestFromData_NoKeyword_DoesNotMatch(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("token="+dummy))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("jira=short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// Suppressed false positives introduced by the hardening pass.
func TestFromData_Suppressed_FalsePositives(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			// 24-char hex git short-SHA fragment in a CHANGELOG line that also
			// names a Jira issue — pure hex is now rejected as a lookalike.
			name: "hex_sha_in_changelog",
			body: "- JIRA-1234 fixed in a3f9c1e2b4d6087512345678",
		},
		{
			// 24-char session/correlation id logged near a bare "jira" prose
			// mention — no assignment-anchored keyword within 48 bytes.
			name: "session_id_near_prose",
			body: "info: posting status update to the jira integration; correlation sessionABCDEFGHIJ12345678 emitted",
		},
		{
			// 24-char dashless build id far (> 48 bytes) from a bare "jira"
			// prose mention — no assignment-anchored keyword in vicinity.
			name: "build_id_far_from_prose",
			body: "the jira board references this artifact; the affected bundle id is buildId7f3a2b9Cd5e6f70a1",
		},
		{
			// all-lowercase 24-char run lacks the mixed-case+digit profile.
			name: "all_lower_run",
			body: "jira_token: abcdefghijklmnopqrstuvwx",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.body))
			if len(res) != 0 {
				t.Fatalf("expected 0 (suppressed), got %d: %+v", len(res), res)
			}
		})
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "ATATT3") {
		t.Fatalf("missing prefix: %q", r)
	}
}
