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
	// Without a secret-intent keyword nearby, candidate must be ignored even
	// though a client_id UUID is present.
	body := "azure_client_id=" + dummyAppID + "\nrandom_token=" + dummyV1Secret
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 without secret-intent keyword, got %d", len(res))
	}
}

// TestFromData_SuppressedFPs asserts the hardening gates drop realistic
// false-positive shapes that survived the old broad gate.
func TestFromData_SuppressedFPs(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			// FQ symbol slug: low entropy after dense run, dotted/kebab
			// package path, near a client_id UUID and a "secret"-ish word.
			name: "fq_symbol_slug",
			body: "azure_client_id=" + dummyAppID +
				"\nclient_secret resolver: com.microsoft.azure.identity_default-credential-chain",
		},
		{
			// Resource-name slug: dash-delimited, short segments, no long
			// dense alnum run, sits next to client_id and a secret keyword.
			name: "resource_name_slug",
			body: "azure deploy: client_secret target my-azure-app-prod-eastus-2024-deploy01 (client_id " + dummyAppID + ")",
		},
		{
			// Subresource-Integrity hash: sha256- prefix, has - and _,
			// placed near an azure config block with a resource UUID and
			// a secret keyword.
			name: "sri_hash",
			body: "azure client_secret block " + dummyAppID +
				`\nintegrity="sha256-47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.body))
			if len(res) != 0 {
				t.Fatalf("expected 0 hits (suppressed FP), got %d: %+v", len(res), res)
			}
		})
	}
}

// TestFromData_TruePositiveStillDetected guards against over-suppression:
// the realistic v1 secret co-located with a secret keyword must survive.
func TestFromData_TruePositiveStillDetected(t *testing.T) {
	body := "azure_client_id=" + dummyAppID + "\nazure_client_secret=" + dummyV1Secret
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	found := false
	for _, r := range res {
		if string(r.Raw) == dummyV1Secret {
			found = true
		}
	}
	if !found {
		t.Fatalf("true-positive v1 secret must still be detected, got %+v", res)
	}
}
