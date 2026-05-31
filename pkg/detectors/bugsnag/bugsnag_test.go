package bugsnag

import (
	"context"
	"strings"
	"testing"
)

const dummy = "0123456789abcdef0123456789abcdef"

func detect(t *testing.T, data string) []string {
	t.Helper()
	res, err := Scanner{}.FromData(context.Background(), false, []byte(data))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	out := make([]string, 0, len(res))
	for _, r := range res {
		if r.Verified {
			t.Fatal("Bugsnag is unverified-by-design (no read endpoint); got Verified=true")
		}
		out = append(out, string(r.Raw))
	}
	return out
}

// --- True positives: still detected after hardening ---

func TestFromData_AssignmentAnchored(t *testing.T) {
	got := detect(t, "BUGSNAG_API_KEY="+dummy)
	if len(got) != 1 || got[0] != dummy {
		t.Fatalf("expected %q, got %v", dummy, got)
	}
}

func TestFromData_TightVicinity(t *testing.T) {
	// bugsnag mention immediately adjacent (well within 40 bytes), no
	// assignment syntax — exercises the fallback path.
	got := detect(t, "bugsnag client booted with "+dummy)
	if len(got) != 1 || got[0] != dummy {
		t.Fatalf("expected vicinity hit, got %v", got)
	}
}

// --- False positives: now SUPPRESSED ---

func TestFP_LockfileIntegrityHash(t *testing.T) {
	// package-lock.json: @bugsnag/core entry whose 32-hex value is an MD5
	// integrity digest, not a key. The "integrity" token poisons it.
	data := `"node_modules/@bugsnag/core": { "integrity": "` + "d41d8cd98f00b204e9800998ecf8427e" + `" }`
	if got := detect(t, data); len(got) != 0 {
		t.Fatalf("lockfile integrity hash should be suppressed, got %v", got)
	}
}

func TestFP_DistantBugsnagMention(t *testing.T) {
	// An unrelated MD5 cache key sitting >40 bytes from a "bugsnag" comment.
	// Old 256-byte radius matched this; the tight radius rejects it.
	data := "# bugsnag integration enabled for the error reporting subsystem here\n" +
		"cache_key: 5d41402abc4b2a76b9719d911017c592"
	if got := detect(t, data); len(got) != 0 {
		t.Fatalf("distant unrelated hash should be suppressed, got %v", got)
	}
}

func TestFP_SourcemapBundleHash(t *testing.T) {
	// asset manifest: bugsnag.min.js bundle name next to its content hash.
	data := `"bugsnag.min.js": { "hash": "098f6bcd4621d373cade4e832627b4f6" }`
	if got := detect(t, data); len(got) != 0 {
		t.Fatalf("sourcemap content hash should be suppressed, got %v", got)
	}
}

func TestFP_LowEntropyLookalike(t *testing.T) {
	// All-zero 32-hex adjacent to a bugsnag key assignment: passes regex and
	// context, dropped by the entropy gate.
	data := "BUGSNAG_API_KEY=00000000000000000000000000000000"
	if got := detect(t, data); len(got) != 0 {
		t.Fatalf("low-entropy lookalike should be suppressed, got %v", got)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	if got := detect(t, "hex="+dummy); len(got) != 0 {
		t.Fatalf("expected 0, got %v", got)
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "01234567") {
		t.Fatalf("missing prefix: %q", r)
	}
}
