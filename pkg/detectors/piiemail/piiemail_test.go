package piiemail

import (
	"context"
	"strings"
	"testing"
)

func TestFromData_FindsEmail(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("contact: alice@example.com please"))
	if len(res) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(res))
	}
	if string(res[0].Raw) != "alice@example.com" {
		t.Errorf("wrong raw: %q", res[0].Raw)
	}
	if res[0].ExtraData["finding_class"] != "pii" {
		t.Errorf("missing finding_class=pii")
	}
	if res[0].ExtraData["pii_kind"] != "email" {
		t.Errorf("missing pii_kind=email")
	}
}

func TestFromData_RejectsInternalHost(t *testing.T) {
	// No TLD shape — internal "user@svc" log lines must NOT fire.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("logged: alice@docker-internal"))
	if len(res) != 0 {
		t.Errorf("internal host without TLD must not match, got %d hits", len(res))
	}
}

func TestFromData_DedupsRepeats(t *testing.T) {
	chunk := []byte("alice@example.com later alice@example.com")
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	if len(res) != 1 {
		t.Fatalf("expected 1 deduped hit, got %d", len(res))
	}
}

func TestFromData_FindsMultipleDistinct(t *testing.T) {
	chunk := []byte("alice@example.com, bob@example.org")
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	if len(res) != 2 {
		t.Fatalf("expected 2 hits, got %d", len(res))
	}
}

func TestRedactEmail(t *testing.T) {
	if got := redactEmail("alice@example.com"); got != "a***@example.com" {
		t.Errorf("redact: %q", got)
	}
	if got := redactEmail("a@x.io"); got != "a@x.io" {
		t.Errorf("short local-part should pass through unchanged: %q", got)
	}
}

func TestKeywordsPresent(t *testing.T) {
	kws := Scanner{}.Keywords()
	if !strings.Contains(strings.Join(kws, ","), "@") {
		t.Error("@ keyword missing")
	}
}
