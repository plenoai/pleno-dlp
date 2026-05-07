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
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("postgresql://u:p@h:5432/d"))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "p" {
		t.Fatalf("password mismatch")
	}
}

func TestFromData_NoUserinfo(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("postgres://db.local:5432/app"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}
