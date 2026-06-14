//go:build detector_unit

package launchnotes

import (
	"context"
	"strings"
	"testing"
)

// High-entropy ln_ body so the entropy gate alone never causes a TP to fail.
const dummy = "ln_AbCdEf0123456789AbCdEf0123456789ABCD"

// Documented authentic shape.
const publicDummy = "public_QKHLUeWw6HxyE5cq9nujHqqX"

func names(in []byte) []string {
	res, err := Scanner{}.FromData(context.Background(), false, in)
	if err != nil {
		panic(err)
	}
	out := make([]string, 0, len(res))
	for _, r := range res {
		out = append(out, string(r.Raw))
	}
	return out
}

func TestFromData_TruePositive_LnWithContext(t *testing.T) {
	// ln_ token WITH a LaunchNotes context keyword within 40 bytes — still detected.
	got := names([]byte("LAUNCHNOTES_KEY=" + dummy))
	if len(got) != 1 || got[0] != dummy {
		t.Fatalf("expected [%s], got %v", dummy, got)
	}
}

func TestFromData_TruePositive_PublicShape(t *testing.T) {
	// Documented public_ token needs no vicinity keyword.
	got := names([]byte("token: " + publicDummy + " // some unrelated code"))
	if len(got) != 1 || got[0] != publicDummy {
		t.Fatalf("expected [%s], got %v", publicDummy, got)
	}
}

func TestFromData_FP_LnNoContext(t *testing.T) {
	// FP fixture 1: a math/util constant beginning ln_, 32+ alnum, NO LaunchNotes
	// keyword in vicinity. Must be suppressed by the vicinity gate.
	in := []byte("const ln_natural_logarithm_constant = ln_e2718281828459045235360287471352")
	if got := names(in); len(got) != 0 {
		t.Fatalf("expected suppressed, got %v", got)
	}
}

func TestFromData_FP_LowEntropyLn(t *testing.T) {
	// FP fixture 2: ln_ token with a LaunchNotes keyword nearby BUT a
	// low-entropy filler body — suppressed by the entropy gate even though
	// vicinity passes.
	in := []byte("launchnotes ln_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if got := names(in); len(got) != 0 {
		t.Fatalf("expected suppressed (low entropy), got %v", got)
	}
}

func TestFromData_FP_CacheKeyNoContext(t *testing.T) {
	// FP fixture 3: a generated cache/etag identifier using an ln_ prefix from
	// an unrelated subsystem; long enough, no provider context nearby.
	in := []byte("export LN_CACHE_KEY=ln_0123456789abcdef0123456789abcdef")
	if got := names(in); len(got) != 0 {
		t.Fatalf("expected suppressed (no context), got %v", got)
	}
}

func TestFromData_FP_Lookalikes(t *testing.T) {
	// Left-delimiter class rejects mid-identifier matches: Linear lin_api_,
	// learn_/login_ style words must not yield an ln_ match.
	in := []byte("learn_api_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx login_ln_token lin_api_abcdef")
	if got := names(in); len(got) != 0 {
		t.Fatalf("expected no lookalike matches, got %v", got)
	}
}

func TestFromData_Negative_TooShort(t *testing.T) {
	if got := names([]byte("ln_short")); len(got) != 0 {
		t.Fatalf("expected 0, got %v", got)
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "ln_AbC") {
		t.Fatalf("missing prefix: %q", r)
	}
}
