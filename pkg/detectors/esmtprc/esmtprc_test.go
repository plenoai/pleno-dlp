//go:build detector_unit

package esmtprc

import (
	"context"
	"testing"
)

func TestFromData_QuotedValue(t *testing.T) {
	data := []byte("identity \"example@gmail.com\"\n" +
		"hostname smtp.gmail.com:587\n" +
		"username \"example@gmail.com\"\n" +
		"password \"R3alSMTPPassZz8k\"\n" +
		"starttls required\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "R3alSMTPPassZz8k" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_BareValue(t *testing.T) {
	// Bare value alongside a sibling directive (hostname) for esmtprc
	// context — see TestFromData_NoContext for the same line without
	// one, which must now be rejected (#293).
	data := []byte("hostname smtp.example.net:587\n" +
		"password R3alSMTPPassZz8k\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "R3alSMTPPassZz8k" {
		t.Fatalf("got %q", res[0].Raw)
	}
}

func TestFromData_Suppressed(t *testing.T) {
	// Each case carries a sibling directive so it exercises the
	// placeholder/shape filters below the context gate, not the gate
	// itself (see TestFromData_NoContext for gate-only rejections).
	const ctx = "hostname smtp.example.net:587\n"
	cases := []struct {
		name string
		data string
	}{
		// leaky-repo's own .esmtprc fixture: the ground-truth value IS
		// the literal placeholder "password" — see package doc comment
		// for why this stays suppressed (same rationale as pgpass's
		// db/.pgpass fixture).
		{"literal password placeholder, quoted", ctx + `password "password"`},
		{"literal password placeholder, bare", ctx + `password password`},
		{"too short", ctx + `password ab`},
		{"trailing text on line breaks grammar", ctx + `password R3alPassZz8k extra-token`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.data))
			if len(res) != 0 {
				t.Fatalf("expected 0, got %d findings for %q: %+v", len(res), tc.data, res)
			}
		})
	}
}

// TestFromData_NoContext is the #293 regression: a `password <value>`
// line that satisfies the bare grammar but has no sibling esmtprc
// directive anywhere in the chunk must not fire. These are the exact
// shapes that produced Workload D false positives on go-git.
func TestFromData_NoContext(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		// plumbing/transport/common.go: exported struct fields
		// `Username string` / `Password string` — both a self-contained
		// `password <token>` line AND (capitalized) a would-be sibling
		// directive line, ruled out by requiring lowercase keywords.
		{"go struct field declaration", "type ProxyOptions struct {\n\tUsername string\n\tPassword string\n}\n"},
		// plumbing/transport/ssh/auth_method.go: a lowercase local
		// variable assignment reuses the "username" token as an
		// identifier, not a directive; the full-line single-token-value
		// anchor rejects the trailing `user.Username` expression.
		{"lowercase identifier assignment", "username = user.Username\n"},
		// plumbing/transport/ssh/auth_method.go doc comment: English
		// prose that happens to end its line right after "password".
		{"english prose, mid-sentence", "// An encryption password should be given if the pemBytes contains a\n// password encrypted PEM block otherwise password should be empty.\n"},
		{"bare password line, no siblings", "password R3alSMTPPassZz8k\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.data))
			if len(res) != 0 {
				t.Fatalf("expected 0, got %d findings for %q: %+v", len(res), tc.data, res)
			}
		})
	}
}
