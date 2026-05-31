package appdynamics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummyClient = "myclient@acme-prod"

// dummySecret matches the documented AppDynamics API Client Secret format: a
// UUID emitted by "Generate Secret" (Splunk AppDynamics "API Clients" docs).
const dummySecret = "face10d5-573e-4a75-8396-afa006fd8f19"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.AppDynamics {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("APPDYNAMICS_CLIENT=" + dummyClient + "\nAPPDYNAMICS_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
	if string(res[0].RawV2) != dummySecret {
		t.Errorf("RawV2 mismatch: %s", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("CLIENT=" + dummyClient + "\nSECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_RejectsGenericHighEntropy guards the FP shape the bare
// [A-Za-z0-9]{20,64} regex used to match: a generic high-entropy alnum run
// sitting right next to the APPDYNAMICS_SECRET assignment. It does not fit the
// documented UUID layout, so it must no longer be reported even though the
// client pair and keyword are present.
func TestFromData_RejectsGenericHighEntropy(t *testing.T) {
	body := []byte("APPDYNAMICS_CLIENT=" + dummyClient +
		"\nAPPDYNAMICS_SECRET=Zk7Qx3Lm9Rt2Vb8Nw5Hy1Pd4Fc6Sg0Aj")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (non-UUID secret must not match), got %d", len(res))
	}
}

// TestFromData_RejectsLowEntropyUUID guards the entropy floor: a UUID-shaped
// placeholder (all zeros) clears secretRe but is not a real secret.
func TestFromData_RejectsLowEntropyUUID(t *testing.T) {
	body := []byte("APPDYNAMICS_CLIENT=" + dummyClient +
		"\nAPPDYNAMICS_SECRET=00000000-0000-0000-0000-000000000000")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy UUID placeholder must not match), got %d", len(res))
	}
}

func TestVerify_Disabled_Default(t *testing.T) {
	v, _ := Scanner{}.Verify(context.Background(), dummyClient+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false default")
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummyClient+":"+dummySecret)
	if err != nil || !v {
		t.Fatalf("err=%v v=%v", err, v)
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummyClient+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummyClient+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}
