//go:build detector_unit

package postgres

import (
	"context"
	"encoding/binary"
	"testing"
)

func TestFromData_PostgresScheme(t *testing.T) {
	body := "DATABASE_URL=postgres://app:s3cr3t@db.example.com:5432/app"
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "s3cr3t" {
		t.Fatalf("password mismatch: %q", res[0].Raw)
	}
	if got := res[0].ExtraData["host"]; got != "db.example.com:5432" {
		t.Fatalf("host: %q", got)
	}
}

func TestFromData_PostgresqlScheme(t *testing.T) {
	// `postgresql://` scheme handling. Password is a non-placeholder, above the
	// degenerate-entropy floor so the semantic gate keeps it (the original
	// single-char `p` fixture was a degenerate value that the entropy floor now
	// correctly rejects — see TestFromData_DegenerateEntropySuppressed).
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("postgresql://u:9aF-x7Q@h:5432/d"))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "9aF-x7Q" {
		t.Fatalf("password mismatch: %q", res[0].Raw)
	}
}

func TestFromData_NoUserinfo(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("postgres://db.local:5432/app"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// --- Negative cases added by the semantic-harden pass (class b). ---

// Documentation / quickstart placeholder: the literal `password`.
func TestFromData_PlaceholderPasswordSuppressed(t *testing.T) {
	body := "postgres://user:password@localhost:5432/mydb"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected placeholder 'password' to be suppressed, got %d: %+v", len(res), res)
	}
}

// docker-compose default: both userinfo halves are the literal `postgres`.
func TestFromData_DockerComposeDefaultSuppressed(t *testing.T) {
	body := "postgresql://postgres:postgres@db:5432/app"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected docker-compose default 'postgres' to be suppressed, got %d: %+v", len(res), res)
	}
}

// Tutorial sentinel credential.
func TestFromData_ChangemeSentinelSuppressed(t *testing.T) {
	body := "postgres://admin:changeme@127.0.0.1/example"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected sentinel 'changeme' to be suppressed, got %d: %+v", len(res), res)
	}
}

// Env-var template in a config file: no literal secret present.
func TestFromData_EnvTemplateSuppressed(t *testing.T) {
	body := "postgres://user:${DB_PASSWORD}@hostplaceholder:5432/app"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected env-var template to be suppressed, got %d: %+v", len(res), res)
	}
}

// `{{...}}` template marker.
func TestFromData_MustacheTemplateSuppressed(t *testing.T) {
	body := "postgres://user:{{password}}@host:5432/app"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected mustache template to be suppressed, got %d: %+v", len(res), res)
	}
}

// Degenerate low-entropy span (repeated char) is rejected by the entropy floor.
func TestFromData_DegenerateEntropySuppressed(t *testing.T) {
	body := "postgres://user:aaaaaaaa@host:5432/app"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected degenerate password to be suppressed, got %d: %+v", len(res), res)
	}
}

// True positive: a realistic random password is STILL detected after hardening.
func TestFromData_RealisticPasswordStillDetected(t *testing.T) {
	body := "postgres://svc:Xk9-mZ2qL7vR8w@db.internal:5432/prod"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected realistic password to be detected, got %d", len(res))
	}
	if string(res[0].Raw) != "Xk9-mZ2qL7vR8w" {
		t.Fatalf("password mismatch: %q", res[0].Raw)
	}
	if got := res[0].ExtraData["user"]; got != "svc" {
		t.Fatalf("user: %q", got)
	}
}

// --- URI parsing tests for Verify ---

func TestShouldSkipHost(t *testing.T) {
	for _, h := range []string{"localhost", "127.0.0.1", "::1", "example.com", "host.example.com"} {
		if !shouldSkipHost(h) {
			t.Errorf("shouldSkipHost(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"db.prod.internal", "pg.example.org", "10.0.0.1"} {
		if shouldSkipHost(h) {
			t.Errorf("shouldSkipHost(%q) = true, want false", h)
		}
	}
}

func TestVerify_InvalidURI(t *testing.T) {
	_, err := Scanner{}.Verify(context.Background(), "://bad\x7furi")
	if err == nil {
		t.Fatal("expected error for invalid URI, got nil")
	}
}

func TestVerify_SkipsLocalhost(t *testing.T) {
	verified, err := Scanner{}.Verify(context.Background(), "postgres://user:pass@localhost:5432/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false for localhost")
	}
}

func TestVerify_SkipsExampleHost(t *testing.T) {
	verified, err := Scanner{}.Verify(context.Background(), "postgres://user:pass@example.com/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false for example.com")
	}
}

func TestVerify_UnreachableHost(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1, routed to nowhere.
	verified, err := Scanner{}.Verify(context.Background(), "postgres://user:pass@192.0.2.1:5432/db")
	if verified {
		t.Fatal("expected verified=false for unreachable host")
	}
	if err == nil {
		t.Fatal("expected a dial error for unreachable host, got nil")
	}
}

func TestVerify_DefaultPort(t *testing.T) {
	// Confirm a URI without an explicit port uses 5432 and does not panic.
	verified, err := Scanner{}.Verify(context.Background(), "postgres://user:pass@192.0.2.1/db")
	if verified {
		t.Fatal("expected verified=false for unreachable host")
	}
	if err == nil {
		t.Fatal("expected a dial error for unreachable host")
	}
}

func TestVerify_PostgresqlScheme(t *testing.T) {
	// postgresql:// scheme also works.
	verified, err := Scanner{}.Verify(context.Background(), "postgresql://user:pass@192.0.2.1:5432/db")
	if verified {
		t.Fatal("expected verified=false for unreachable host")
	}
	if err == nil {
		t.Fatal("expected a dial error for unreachable host")
	}
}

// TestComputeMD5Password verifies the PostgreSQL MD5 password hash algorithm.
func TestComputeMD5Password(t *testing.T) {
	// Known test vector: PostgreSQL MD5 password for user "user", password "pass",
	// salt [0x01, 0x02, 0x03, 0x04].
	result := computeMD5Password("user", "pass", []byte{0x01, 0x02, 0x03, 0x04})
	if len(result) < 3 || result[:3] != "md5" {
		t.Fatalf("expected md5 prefix, got %q", result)
	}
	// 3 ("md5") + 32 (hex md5) = 35 chars
	if len(result) != 35 {
		t.Fatalf("expected 35 chars, got %d: %q", len(result), result)
	}

	// Determinism check.
	result2 := computeMD5Password("user", "pass", []byte{0x01, 0x02, 0x03, 0x04})
	if result != result2 {
		t.Fatal("non-deterministic MD5 password computation")
	}
}

// TestBuildStartupMessage verifies the startup message structure.
func TestBuildStartupMessage(t *testing.T) {
	msg := buildStartupMessage("testuser", "testdb")

	if len(msg) < 8 {
		t.Fatalf("message too short: %d bytes", len(msg))
	}

	// First 4 bytes = total length (big-endian).
	totalLen := binary.BigEndian.Uint32(msg[0:4])
	if int(totalLen) != len(msg) {
		t.Fatalf("length mismatch: header says %d, actual %d", totalLen, len(msg))
	}

	// Next 4 bytes = protocol version (196608 = 3.0).
	protoVer := binary.BigEndian.Uint32(msg[4:8])
	if protoVer != 196608 {
		t.Fatalf("protocol version: got %d, want 196608", protoVer)
	}
}

// TestBuildTerminate verifies the terminate message structure.
func TestBuildTerminate(t *testing.T) {
	msg := buildTerminate()
	if len(msg) != 5 {
		t.Fatalf("expected 5 bytes, got %d", len(msg))
	}
	if msg[0] != 'X' {
		t.Fatalf("expected 'X', got %c", msg[0])
	}
	msgLen := binary.BigEndian.Uint32(msg[1:5])
	if msgLen != 4 {
		t.Fatalf("expected length 4, got %d", msgLen)
	}
}
