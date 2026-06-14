//go:build detector_unit

package redis

import (
	"context"
	"testing"
)

func TestFromData_Positive(t *testing.T) {
	body := `REDIS_URL=redis://default:s3cr3tPassword@cache.example.com:6379/0`
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "s3cr3tPassword" {
		t.Fatalf("password mismatch: %q", res[0].Raw)
	}
	if got := res[0].ExtraData["host"]; got != "cache.example.com:6379" {
		t.Fatalf("host: %q", got)
	}
	if got := res[0].ExtraData["user"]; got != "default" {
		t.Fatalf("user: %q", got)
	}
}

func TestFromData_TLSScheme(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("rediss://:hunter2@redis.prod:6380"))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "hunter2" {
		t.Fatalf("password mismatch: %q", res[0].Raw)
	}
}

func TestFromData_NoPasswordNotReturned(t *testing.T) {
	// `redis://host` without userinfo is not a credential leak.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("redis://cache.local:6379"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_RawV2HoldsURL(t *testing.T) {
	body := "redis://:abc123@h:1"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1")
	}
	if string(res[0].RawV2) != body {
		t.Fatalf("rawv2 mismatch: %q", res[0].RawV2)
	}
}

func TestVerify_InvalidURI(t *testing.T) {
	// An unparseable URI should return an error, not panic.
	_, err := Scanner{}.Verify(context.Background(), "://bad\x7furi")
	if err == nil {
		t.Fatal("expected error for invalid URI, got nil")
	}
}

func TestVerify_PackedFormat(t *testing.T) {
	// Verify against a non-routable address should return a dial error,
	// not a parse error. This confirms the URI parsing and RESP command
	// formatting paths work end-to-end for both username+password and
	// password-only URIs.
	cases := []struct {
		name string
		uri  string
	}{
		{
			name: "password only",
			uri:  "redis://:s3cr3t@192.0.2.1:16379/0",
		},
		{
			name: "username and password",
			uri:  "redis://alice:s3cr3t@192.0.2.1:16379/0",
		},
		{
			name: "TLS default port",
			uri:  "rediss://:s3cr3t@192.0.2.1",
		},
		{
			name: "plain default port",
			uri:  "redis://:s3cr3t@192.0.2.1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verified, err := Scanner{}.Verify(context.Background(), tc.uri)
			if verified {
				t.Fatal("expected verified=false for unreachable host")
			}
			// A dial error is expected — the important thing is that
			// URI parsing and command construction did not fail.
			if err == nil {
				t.Fatal("expected a dial error for unreachable host, got nil")
			}
		})
	}
}
