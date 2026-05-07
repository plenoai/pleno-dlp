package piicc

import (
	"context"
	"testing"
)

func TestLuhnValid(t *testing.T) {
	for _, in := range []string{
		"4111111111111111", // canonical Visa test card
		"5555555555554444", // MC test card
		"378282246310005",  // Amex test card
		"6011111111111117", // Discover test card
	} {
		if !luhnValid([]byte(in)) {
			t.Errorf("expected valid Luhn for %q", in)
		}
	}
	for _, in := range []string{
		"4111111111111112", // last digit off
		"1234567890123456",
	} {
		if luhnValid([]byte(in)) {
			t.Errorf("expected invalid Luhn for %q", in)
		}
	}
}

func TestFromData_FindsValidCard(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("card: 4111-1111-1111-1111"))
	if len(res) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(res))
	}
	if res[0].ExtraData["network"] != "visa" {
		t.Errorf("network: %q", res[0].ExtraData["network"])
	}
	if res[0].Redacted != "411111******1111" {
		t.Errorf("redact: %q", res[0].Redacted)
	}
	if res[0].ExtraData["finding_class"] != "pii" {
		t.Error("finding_class missing")
	}
}

func TestFromData_RejectsLuhnFailure(t *testing.T) {
	// 16-digit numeric that fails Luhn — typical IMEI / order id shape.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("order: 1234567890123456"))
	if len(res) != 0 {
		t.Errorf("expected 0 hits on non-Luhn 16-digit, got %d", len(res))
	}
}

func TestFromData_FindsAmex(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("amex: 378282246310005"))
	if len(res) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(res))
	}
	if res[0].ExtraData["network"] != "amex" {
		t.Errorf("network: %q", res[0].ExtraData["network"])
	}
}

func TestFromData_DedupsRepeats(t *testing.T) {
	chunk := []byte("4111-1111-1111-1111 again 4111111111111111")
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	if len(res) != 1 {
		t.Fatalf("normalised dedup expected 1, got %d", len(res))
	}
}
