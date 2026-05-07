package azureapp

import (
	"context"
	"testing"
)

const dummyAppID = "12345678-90ab-cdef-1234-567890abcdef"
const dummyV1Secret = "abc.de_fgh-ijkl0123456789mnopqrstuv"

func TestFromData_PairLegacy(t *testing.T) {
	body := "azure_client_id=" + dummyAppID + "\nazure_client_secret=" + dummyV1Secret
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("expected at least 1 hit")
	}
	found := false
	for _, r := range res {
		if string(r.Raw) == dummyV1Secret && string(r.RawV2) == dummyAppID {
			found = true
			if r.Severity != 5 {
				t.Fatalf("expected critical, got %d", r.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("expected pair {%s, %s}; got %+v", dummyV1Secret, dummyAppID, res)
	}
}

func TestFromData_RejectTildeShape(t *testing.T) {
	// Tilde-bearing secrets belong to pkg/detectors/azuread, not here.
	tilde := "abc~de_fgh-ijkl0123456789mnopqrstuv"
	body := "azure_client_id=" + dummyAppID + "\nazure_client_secret=" + tilde
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	for _, r := range res {
		if string(r.Raw) == tilde {
			t.Fatalf("azureapp should not claim tilde-bearing secrets, got %v", r)
		}
	}
}

func TestFromData_NoUUID(t *testing.T) {
	// Without a client_id UUID nearby, candidate must be ignored.
	body := "azure_client_secret=" + dummyV1Secret
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 without client_id, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := "ssh_key_id=" + dummyAppID + "\nrandom_token=" + dummyV1Secret
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 without azure keyword, got %d", len(res))
	}
}
