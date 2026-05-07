package tailscale

import (
	"context"
	"strings"
	"testing"
)

const dummyAuth = "tskey-auth-kFcd1234567890-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEF"
const dummyAPI = "tskey-api-kFcd1234567890-ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkj"

func TestFromData_Auth(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("TS_AUTHKEY="+dummyAuth))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("Tailscale is unverified-by-design (provisioning use); got Verified=true")
	}
	if string(res[0].Raw) != dummyAuth {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_API(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("TS_API_KEY="+dummyAPI))
	if len(res) != 1 {
		t.Fatalf("expected 1 api hit, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("tskey-short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyAuth)
	if r == dummyAuth {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "tskey-auth-") {
		t.Fatalf("missing prefix: %q", r)
	}
}
