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
