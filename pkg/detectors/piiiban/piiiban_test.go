package piiiban

import (
	"context"
	"testing"
)

func TestMod97_KnownValid(t *testing.T) {
	// Canonical IBAN samples from spec docs.
	for _, in := range []string{
		"DE89370400440532013000", // Germany sample
		"GB29NWBK60161331926819", // UK sample
		"FR1420041010050500013M02606",
	} {
		if !mod97Valid(in) {
			t.Errorf("expected valid for %q", in)
		}
	}
}

func TestMod97_InvalidChecksum(t *testing.T) {
	for _, in := range []string{
		"DE89370400440532013001", // last digit bumped
		"GB29NWBK60161331926818",
	} {
		if mod97Valid(in) {
			t.Errorf("expected invalid for %q", in)
		}
	}
}

func TestFromData_FindsValidIBAN(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("iban: DE89 3704 0044 0532 0130 00"))
	if len(res) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(res))
	}
	if res[0].ExtraData["country"] != "DE" {
		t.Errorf("country: %q", res[0].ExtraData["country"])
	}
	if res[0].ExtraData["finding_class"] != "pii" {
		t.Error("finding_class missing")
	}
}

func TestFromData_RejectsBadLength(t *testing.T) {
	// DE wants exactly 22 chars; this is 21.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("iban: DE893704004405320130 0"))
	if len(res) != 0 {
		t.Errorf("wrong length must not match, got %d", len(res))
	}
}

func TestFromData_NormalisesSpaces(t *testing.T) {
	a, _ := Scanner{}.FromData(context.Background(), false, []byte("DE89 3704 0044 0532 0130 00"))
	b, _ := Scanner{}.FromData(context.Background(), false, []byte("DE89370400440532013000"))
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 hit each, got %d / %d", len(a), len(b))
	}
}

func TestRedactIBAN(t *testing.T) {
	got := redactIBAN("DE89370400440532013000")
	if got != "DE89**************3000" {
		t.Errorf("redact: %q", got)
	}
}
