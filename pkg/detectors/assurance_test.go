package detectors

import (
	"encoding/json"
	"testing"
)

func TestVerificationAssuranceString(t *testing.T) {
	tests := []struct {
		assurance VerificationAssurance
		want      string
	}{
		{AssuranceUnknown, "unknown"},
		{AssuranceHeuristic, "heuristic"},
		{AssuranceResponseConfirmed, "response-confirmed"},
		{AssuranceProviderConfirmed, "provider-confirmed"},
		{VerificationAssurance(255), "unknown"},
	}
	for _, tc := range tests {
		if got := tc.assurance.String(); got != tc.want {
			t.Errorf("VerificationAssurance(%d).String() = %q, want %q", tc.assurance, got, tc.want)
		}
	}
}

func TestVerificationAssuranceMarshalsAsJSONText(t *testing.T) {
	got, err := json.Marshal(AssuranceProviderConfirmed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != `"provider-confirmed"` {
		t.Fatalf("JSON = %s, want provider-confirmed string", got)
	}
}

func TestVerificationAssuranceOrdering(t *testing.T) {
	if !(AssuranceUnknown < AssuranceHeuristic &&
		AssuranceHeuristic < AssuranceResponseConfirmed &&
		AssuranceResponseConfirmed < AssuranceProviderConfirmed) {
		t.Fatal("verification assurance constants must remain ordered from weakest to strongest")
	}
}
