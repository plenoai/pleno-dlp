package piissn

import (
	"context"
	"testing"
)

func TestFromData_ValidSSN(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("ssn=123-45-6789"))
	if len(res) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(res))
	}
	if string(res[0].Raw) != "123-45-6789" {
		t.Errorf("raw: %q", res[0].Raw)
	}
	if res[0].Redacted != "***-**-6789" {
		t.Errorf("redact: %q", res[0].Redacted)
	}
	if res[0].ExtraData["finding_class"] != "pii" {
		t.Error("finding_class missing")
	}
}

func TestFromData_RejectsAllZeros(t *testing.T) {
	for _, in := range []string{"000-12-3456", "123-00-4567", "123-45-0000"} {
		res, _ := Scanner{}.FromData(context.Background(), false, []byte("ssn: "+in))
		if len(res) != 0 {
			t.Errorf("expected 0 hits for %q, got %d", in, len(res))
		}
	}
}

func TestFromData_RejectsReservedAreas(t *testing.T) {
	for _, in := range []string{"666-12-3456", "900-12-3456", "987-65-4321"} {
		res, _ := Scanner{}.FromData(context.Background(), false, []byte("ssn: "+in))
		if len(res) != 0 {
			t.Errorf("expected 0 hits for reserved area %q, got %d", in, len(res))
		}
	}
}

func TestFromData_RejectsKnownExamples(t *testing.T) {
	for _, in := range []string{"078-05-1120", "219-09-9999"} {
		res, _ := Scanner{}.FromData(context.Background(), false, []byte("ssn: "+in))
		if len(res) != 0 {
			t.Errorf("expected 0 hits for known example %q, got %d", in, len(res))
		}
	}
}

func TestFromData_RejectsNoHyphenForm(t *testing.T) {
	// 9-digit numeric without hyphens is too FP-prone (every order id).
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("ssn: 123456789"))
	if len(res) != 0 {
		t.Errorf("no-hyphen form must not match, got %d", len(res))
	}
}

func TestFromData_DedupsRepeats(t *testing.T) {
	chunk := []byte("123-45-6789 again 123-45-6789")
	res, _ := Scanner{}.FromData(context.Background(), false, chunk)
	if len(res) != 1 {
		t.Fatalf("expected dedup, got %d", len(res))
	}
}
