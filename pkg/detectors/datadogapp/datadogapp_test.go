package datadogapp

import (
	"context"
	"testing"
)

const dummyApp = "0123456789abcdef0123456789abcdef01234567"
const dummyAPI = "abcdef0123456789abcdef0123456789"

func TestFromData_StandaloneApp(t *testing.T) {
	body := "DD-APPLICATION-KEY: " + dummyApp
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyApp {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("sha1="+dummyApp))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_SkipPaired(t *testing.T) {
	// When a 32-hex API key sits adjacent, the `datadog` detector owns this;
	// datadogapp must not also fire.
	body := "DD_API_KEY=" + dummyAPI + "\nDD_APPLICATION_KEY=" + dummyApp
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 (paired path delegates to datadog), got %d", len(res))
	}
}
