//go:build detector_unit

package unixcrypthash

import (
	"context"
	"testing"
)

// The hash payloads below are synthetically generated (not copied from
// any real system or fixture repo) but satisfy the exact charset/length
// constraints of each crypt format so the regex exercises real match
// boundaries.
const (
	sha512CryptSalt = "Kx9QvLmZ3nRt7YbW"
	sha512CryptHash = "UuVTAIjvFu7WICPhDeOZIiBOB/Y6sHrFH2ZUCr/lgotu2iXW"
	apr1Salt        = "tp8glkbm"
	apr1Hash        = "7GboIRoL3u6aHwnMztVuaP.coUNEhE"
	bcryptPayload   = "odJFCrnl2edlBDdz1C5Jau2RJtBRnlWmTSHf6pWkLUyifDLkDmWJ6"
)

func TestFromData_SHA512Crypt(t *testing.T) {
	data := []byte("ubuntu:$6$" + sha512CryptSalt + "$" + sha512CryptHash + ":0:99999:7:::\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if res[0].ExtraData["user"] != "ubuntu" {
		t.Fatalf("user = %q", res[0].ExtraData["user"])
	}
}

func TestFromData_Apr1Htpasswd(t *testing.T) {
	data := []byte("admin:$apr1$" + apr1Salt + "$" + apr1Hash + "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
}

func TestFromData_ProftpdTail(t *testing.T) {
	data := []byte("root:$6$" + sha512CryptSalt + "$" + sha512CryptHash + ":3044:3045::/home/root:/bin/ftpsh\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
}

func TestFromData_Bcrypt(t *testing.T) {
	data := []byte("svc_api:$2y$10$" + bcryptPayload + "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
}

func TestFromData_ApacheLegacyTag(t *testing.T) {
	data := []byte("legacyuser:{SHA}" + "K5+bLdgWdRe3fkQXe/M5CJvHXik=\n")
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
}

func TestFromData_ShadowFile(t *testing.T) {
	// Locked (`*`) and passwordless (empty field) accounts must not be
	// flagged; only the one real hash should surface.
	data := []byte(
		"root::17431:0:99999:7:::\n" +
			"daemon:*:17431:0:99999:7:::\n" +
			"www-data:*:17431:0:99999:7:::\n" +
			"ubuntu:$6$" + sha512CryptSalt + "$" + sha512CryptHash + ":0:99999:7:::\n",
	)
	res, _ := Scanner{}.FromData(context.Background(), false, data)
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if res[0].ExtraData["user"] != "ubuntu" {
		t.Fatalf("user = %q", res[0].ExtraData["user"])
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"locked account", "daemon:*:17431:0:99999:7:::\n"},
		{"empty hash field", "root::17431:0:99999:7:::\n"},
		{"known bcryptjs example hash", "demo:$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy\n"},
		{"not a crypt hash", "someuser:not-a-real-hash-just-text\n"},
		{"too-short hash body", "u:$6$abc$def\n"},
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
