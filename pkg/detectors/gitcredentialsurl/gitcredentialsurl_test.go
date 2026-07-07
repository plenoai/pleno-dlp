//go:build detector_unit

package gitcredentialsurl

import (
	"context"
	"testing"
)

// TestFromData_RawReservedChars mirrors the shape git's credential-store
// format actually produces: an email-like username (containing `@`) and
// a password containing an unescaped `#` — both of which cause
// net/url.Parse to mis-split the URL, which is exactly the gap this
// detector exists to close (see basicAuthWouldCatch's doc comment).
func TestFromData_RawReservedChars(t *testing.T) {
	data := []byte("https://ops@example.com:Qx7!#Zeta9@github.example.com\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if string(res[0].Raw) != "Qx7!#Zeta9" {
		t.Fatalf("password = %q", res[0].Raw)
	}
	if res[0].ExtraData["user"] != "ops@example.com" {
		t.Fatalf("user = %q", res[0].ExtraData["user"])
	}
	if res[0].ExtraData["host"] != "github.example.com" {
		t.Fatalf("host = %q", res[0].ExtraData["host"])
	}
}

// TestFromData_DefersToBasicAuth verifies this detector stays silent on
// the well-formed case that pkg/detectors/basicauth already handles —
// no double-reporting under two DetectorTypes for the same secret.
func TestFromData_DefersToBasicAuth(t *testing.T) {
	data := []byte("https://alice:Sup3r-Duper-Secret9@db.example.com\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 0 {
		t.Fatalf("expected 0 (deferred to basicauth), got %d: %+v", len(res), res)
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"no password", "https://justauser@host.example.com\n"},
		{"placeholder password", "https://user@host.example.com:password@host.example.com\n"},
		{"templated password", "https://user@host.example.com:${DB_PASS}@host.example.com\n"},
		{"not a URL line", "this is not a URL at all, just prose about hosts and users\n"},
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

func TestWantsFullChunk(t *testing.T) {
	if !(Scanner{}.WantsFullChunk()) {
		t.Fatal("expected WantsFullChunk() == true")
	}
}
