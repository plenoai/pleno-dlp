package aws

import (
	"context"
	"testing"
)

func TestFromData_Positive(t *testing.T) {
	data := []byte(`
aws_access_key_id     = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`)
	res, err := Scanner{}.FromData(context.Background(), false, data)
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res))
	}
	if string(res[0].Raw) != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("Raw = %s", res[0].Raw)
	}
	if len(res[0].RawV2) == 0 {
		t.Errorf("expected RawV2 to be populated with paired secret")
	}
	if res[0].Redacted != "AKIA..." {
		t.Errorf("Redacted = %q", res[0].Redacted)
	}
}

func TestFromData_Negative(t *testing.T) {
	data := []byte("nothing of interest here, just text without an aws key id")
	res, err := Scanner{}.FromData(context.Background(), false, data)
	if err != nil {
		t.Fatalf("FromData err: %v", err)
	}
	if len(res) != 0 {
		t.Fatalf("expected 0 results, got %d", len(res))
	}
}

func TestKeywords(t *testing.T) {
	kws := Scanner{}.Keywords()
	if len(kws) == 0 {
		t.Fatal("Keywords must not be empty")
	}
	if kws[0] != "AKIA" {
		t.Errorf("expected AKIA prefix keyword, got %v", kws)
	}
}

func TestSplitPair(t *testing.T) {
	id, sk, ok := splitPair("AKIAEXAMPLE:secretpart")
	if !ok || id != "AKIAEXAMPLE" || sk != "secretpart" {
		t.Errorf("splitPair = %q %q %v", id, sk, ok)
	}
	if _, _, ok := splitPair("nopairhere"); ok {
		t.Error("splitPair should fail without colon")
	}
}
