package vault

import (
	"context"
	"strings"
	"testing"
)

const dummyHvs = "hvs.AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG"
const dummyLegacy = "s.AbCdEfGhIjKlMnOpQrStUvWx"

func TestFromData_Modern(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("VAULT_TOKEN="+dummyHvs))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("Vault is unverified-by-design (server URL unknown); got Verified=true")
	}
	if string(res[0].Raw) != dummyHvs {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Legacy(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("VAULT_TOKEN="+dummyLegacy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyLegacy {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("hvs.short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyHvs)
	if r == dummyHvs {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "hvs.Ab") {
		t.Fatalf("missing prefix: %q", r)
	}
}
