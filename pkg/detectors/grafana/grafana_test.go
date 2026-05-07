package grafana

import (
	"context"
	"strings"
	"testing"
)

// glsa_ + 32 base62 + _ + 8 lowercase hex.
const dummy = "glsa_AbCdEfGhIjKlMnOpQrStUvWxYz012345_0a1b2c3d"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("GRAFANA_TOKEN="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("Grafana is unverified-by-design (host unknown)")
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("glsa_short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "glsa_AbC") {
		t.Fatalf("missing prefix: %q", r)
	}
}
