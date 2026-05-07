package salesforcerefresh

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var dummy = "5Aep861" + strings.Repeat("A", 60) + "._-Z0"

func TestFromData_Positive(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), true, []byte("SF_REFRESH="+dummy))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("Salesforce refresh tokens are unverified-by-design")
	}
	if res[0].Severity != detectors.SeverityMedium {
		t.Fatalf("expected Medium severity, got %v", res[0].Severity)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("5Aep861short"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "5Aep861") {
		t.Fatalf("missing prefix: %q", r)
	}
}
