package modal

import (
	"context"
	"strings"
	"testing"
)

const dummyID = "ak-AbCdEf0123456789AbCd"
const dummySecret = "as-ZyXwVu9876543210ZyXw"

func TestFromData_Pair(t *testing.T) {
	body := []byte("MODAL_TOKEN_ID=" + dummyID + "\nMODAL_TOKEN_SECRET=" + dummySecret)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyID {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("rawv2 mismatch: %q", res[0].RawV2)
	}
}

func TestFromData_OnlyID(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("MODAL_TOKEN_ID="+dummyID))
	if len(res) != 0 {
		t.Fatalf("expected 0 without secret, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "ak-AbCdE") {
		t.Fatalf("missing prefix: %q", r)
	}
}
