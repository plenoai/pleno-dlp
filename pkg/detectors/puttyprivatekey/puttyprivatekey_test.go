//go:build detector_unit

package puttyprivatekey

import (
	"context"
	"strings"
	"testing"
)

const syntheticUnencrypted = `PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Comment: synthetic-fixture-not-a-real-key
Public-Lines: 4
QUFBQUIzTnphQzF5YzJFQUFBQUJKUUFBQVFFQXFqTk9WZ0h6TW9nSVQ2Zk1SQkVv
ZjBTZkV3Rk9QM1JqUEZuWnFkV1JBTHNXZWl4NEJTZVFERWJVdTJWTk5PY0lYd2sw
dEJIclZLR2NZVWhLU2VCMWlHb1o0aE5oQmJ4UVE0dExUb1Y5ck9TVU1SQmZUbGtM
akhtaGRZS3o0bGdlSm5DVWs2dGV5Q0YrTFdBTEJnRQ==
Private-Lines: 4
Y3ludGhldGljIHByaXZhdGUga2V5IG1hdGVyaWFsIGZvciB0ZXN0aW5nIG9ubHks
IG5vdCBhIHJlYWwga2V5LCBqdXN0IHBhZGRpbmcgYnl0ZXMgdG8gbG9vayByaWdo
dCBzaGFwZSBmb3IgdGhlIHVuaXQgdGVzdCBmaXh0dXJlIGJlbG93IGhlcmUgbm93
IQ==
Private-MAC: 6730c52e494d4aba1191485053ca6f47bb619d2b
`

const syntheticEncrypted = `PuTTY-User-Key-File-3: ssh-ed25519
Encryption: aes256-cbc
Comment: synthetic-encrypted-fixture
Key-Derivation: Argon2id
Key-Length: 32
Public-Lines: 2
QUFBQUMzTnphQzFsWkRJMU5URUFBQUFJZDNsRlV6a3hUV0k=
Private-Lines: 2
c3ludGhldGljIGVuY3J5cHRlZCBwcml2YXRlIGtleSBkYXRh
Private-MAC: 1122334455667788990011223344556677889900
`

func TestFromData_Unencrypted(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(syntheticUnencrypted))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if !strings.Contains(string(res[0].Raw), "PuTTY-User-Key-File-2: ssh-rsa") {
		t.Fatalf("raw missing header: %q", res[0].Raw)
	}
	if !strings.Contains(string(res[0].Raw), "Private-MAC: 6730c52e494d4aba1191485053ca6f47bb619d2b") {
		t.Fatalf("raw missing trailing Private-MAC line: %q", res[0].Raw)
	}
	if res[0].ExtraData["algorithm"] != "ssh-rsa" {
		t.Fatalf("got algorithm %q", res[0].ExtraData["algorithm"])
	}
	if res[0].ExtraData["format_version"] != "2" {
		t.Fatalf("got format_version %q", res[0].ExtraData["format_version"])
	}
	if res[0].ExtraData["ppk_encrypted"] != "false" {
		t.Fatalf("expected ppk_encrypted=false, got %q", res[0].ExtraData["ppk_encrypted"])
	}
}

func TestFromData_Encrypted(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(syntheticEncrypted))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(res), res)
	}
	if res[0].ExtraData["ppk_encrypted"] != "true" {
		t.Fatalf("expected ppk_encrypted=true, got %q", res[0].ExtraData["ppk_encrypted"])
	}
	if res[0].ExtraData["encryption"] != "aes256-cbc" {
		t.Fatalf("got encryption %q", res[0].ExtraData["encryption"])
	}
	if res[0].ExtraData["format_version"] != "3" {
		t.Fatalf("got format_version %q", res[0].ExtraData["format_version"])
	}
}

func TestFromData_Suppressed(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"no PuTTY header at all", "-----BEGIN RSA PRIVATE KEY-----\nfoo\n-----END RSA PRIVATE KEY-----"},
		{"header present but no closing Private-MAC line", "PuTTY-User-Key-File-2: ssh-rsa\nEncryption: none\nComment: incomplete\n"},
		{"unrelated text mentioning putty", "we use putty to connect to our servers"},
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
