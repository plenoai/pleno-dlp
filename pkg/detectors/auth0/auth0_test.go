package auth0

import (
	"context"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a high-entropy JWT-shaped token (random-looking base64url signature)
// so it clears the entropy gate. Not a real token.
const dummy = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuYXV0aDAuY29tLyJ9.qX7Kp2mZ9vR4tL8wN3bF6cH1sJ0aD5eG7uY2iO9pQwE"

func TestFromData_PositiveWithAuth0Host(t *testing.T) {
	// Auth0 tenant host within the tight window — true positive, still detected.
	body := []byte("// token for acme.auth0.com\nAUTH0_TOKEN=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("Auth0 is unverified-by-design (audience unknown)")
	}
	// Class-b: severity follows the detector default for an unverified hit,
	// no longer hard-coded Critical.
	if res[0].Severity != detectors.DefaultSeverity(detectors.Auth0, false) {
		t.Fatalf("expected default unverified severity, got %v", res[0].Severity)
	}
}

func TestFromData_PositiveBareAuth0DotCom(t *testing.T) {
	body := []byte("management.auth0 token: " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 1 {
		t.Fatalf("expected 1 with management.auth0 context, got %d", len(res))
	}
}

// FP1: a JWT sitting next to an unrelated auth0 import path. The bare substring
// "auth0" used to fire this; the auth0.com/management context gate suppresses it.
func TestFromData_SuppressImportPath(t *testing.T) {
	body := []byte("import \"github.com/auth0/go-jwt-middleware\"\nvar t = \"" + dummy + "\"")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 near auth0 import path (no auth0.com context), got %d", len(res))
	}
}

// FP2: the canonical RFC-7519 / jwt.io example JWT in an auth0-titled README.
func TestFromData_SuppressRFC7519Example(t *testing.T) {
	body := []byte("# Auth0 quickstart (acme.auth0.com)\nExample: " + rfc7519Example)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for canonical RFC-7519 example, got %d", len(res))
	}
}

// FP3: low-entropy documentation JWT with a filler signature segment.
func TestFromData_SuppressLowEntropySample(t *testing.T) {
	sample := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.aaaaaaaaaaaaaaaaaaaaaaaa"
	body := []byte("acme.auth0.com sample token: " + sample)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for low-entropy sample signature, got %d", len(res))
	}
}

// FP4: unsigned alg:"none" token must be excluded even with auth0.com nearby.
func TestFromData_SuppressUnsignedToken(t *testing.T) {
	// header {"alg":"none","typ":"JWT"} base64url-encoded.
	unsigned := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJhdXRoMCJ9.qX7Kp2mZ9vR4tL8wN3bF6cH1sJ0aD5eG7uY2iO9pQwE"
	body := []byte("acme.auth0.com " + unsigned)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 for unsigned alg:none token, got %d", len(res))
	}
}

func TestFromData_NoContext(t *testing.T) {
	body := []byte("X=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 without auth0 context (generic JWT detector handles this), got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummy)
	if r == dummy {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "eyJhbGciOiJI") {
		t.Fatalf("missing prefix: %q", r)
	}
}
