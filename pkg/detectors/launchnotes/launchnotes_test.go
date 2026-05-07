package launchnotes

import (
	"context"
	"strings"
	"testing"
)

const dummy = "ln_AbCdEf0123456789AbCdEf0123456789ABCD"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("LAUNCHNOTES_KEY="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Negative(t *testing.T) {
	// Too short — fewer than 32 suffix chars.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("ln_short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
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
