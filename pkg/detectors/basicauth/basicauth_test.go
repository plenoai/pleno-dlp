package basicauth

import (
	"context"
	"testing"
)

func TestFromData_HTTPS(t *testing.T) {
	// "admin" is a denylisted placeholder user; use a real-looking user so
	// this remains a true-positive fixture.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("https://svcacct:p4ssw0rdXz@api.example.com/v1"))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "p4ssw0rdXz" {
		t.Fatalf("password: %q", res[0].Raw)
	}
	if got := res[0].ExtraData["user"]; got != "svcacct" {
		t.Fatalf("user: %q", got)
	}
}

func TestFromData_FTP(t *testing.T) {
	// "secret" is a denylisted placeholder; use a realistic password.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("ftp://user:Gh7xQ2pL9@files.example.com"))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "Gh7xQ2pL9" {
		t.Fatalf("password: %q", res[0].Raw)
	}
}

// FP fixtures that must now be SUPPRESSED by the hardening gates.
func TestFromData_SuppressedPlaceholders(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{"lowercase doc placeholder", "https://username:password@hostname/path"},
		{"uppercase doc placeholder", "https://USER:PASSWORD@api.example.com/v1"},
		{"tutorial example creds", "https://foo:bar@example.com"},
		{"git x-oauth-basic literal", "https://token:x-oauth-basic@github.com/org/repo.git"},
		{"env-var template", "https://admin:${DB_PASSWORD}@db.internal/app"},
		{"angle-bracket template", "https://user:<password>@host/db"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.uri))
			if len(res) != 0 {
				t.Fatalf("expected 0 (suppressed), got %d for %q", len(res), tc.uri)
			}
		})
	}
}

// True-positive fixtures that must STILL be detected after hardening.
func TestFromData_StillDetected(t *testing.T) {
	cases := []struct {
		name string
		uri  string
		pw   string
	}{
		{"realistic password", "https://svc:Gh7xQ2pL9@api.example.com/v1", "Gh7xQ2pL9"},
		{"short but real", "https://deploy:k9Xq2z@internal.host/path", "k9Xq2z"},
		{"percent-encoded password decoded", "https://app:p4ss%40w0rd@svc.example.com", "p4ss@w0rd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.uri))
			if len(res) != 1 {
				t.Fatalf("expected 1, got %d for %q", len(res), tc.uri)
			}
			if string(res[0].Raw) != tc.pw {
				t.Fatalf("password: got %q want %q", res[0].Raw, tc.pw)
			}
		})
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
