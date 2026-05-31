package postgres

import (
	"context"
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
