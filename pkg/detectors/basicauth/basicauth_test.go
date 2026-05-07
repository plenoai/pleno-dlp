package basicauth

import (
	"context"
	"testing"
)

func TestFromData_HTTPS(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("https://admin:p4ssword@api.example.com/v1"))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "p4ssword" {
		t.Fatalf("password: %q", res[0].Raw)
	}
	if got := res[0].ExtraData["user"]; got != "admin" {
		t.Fatalf("user: %q", got)
	}
}

func TestFromData_FTP(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("ftp://user:secret@files.example.com"))
	if len(res) != 1 {
		t.Fatalf("expected 1")
	}
}

func TestFromData_NoUserinfo(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("https://example.com/login"))
	if len(res) != 0 {
		t.Fatalf("expected 0")
	}
}

func TestFromData_EmptyUser(t *testing.T) {
	// `:p@h` matches the regex shape, but empty user is a template, not a leak.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("https://:p@host"))
	if len(res) != 0 {
		t.Fatalf("expected 0 with empty user, got %d", len(res))
	}
}

func TestFromData_OwnedSchemeIgnored(t *testing.T) {
	// We DO match http(s)/ftp(s) only; postgres/etc. aren't matched at the
	// regex level by basicauth. This test confirms we don't accidentally
	// match a postgres URL via basicauth.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("postgres://u:p@h:5432"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}
