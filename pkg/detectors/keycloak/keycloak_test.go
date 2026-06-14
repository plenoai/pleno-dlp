//go:build detector_unit

package keycloak

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummySecret is a 32-char [A-Za-z0-9] value matching Keycloak's documented
// SecretGenerator default (SECRET_LENGTH_256_BITS=32, ALPHANUM). High entropy
// so it clears the 3.5 floor. Not a real credential.
const dummySecret = "aZ9kQ2mB7pX4vL1nR6tW3yE8sD0fG5hJ"

// dummyID is an admin-chosen client_id — free-form, not length-pinned.
const dummyID = "my-keycloak-client"

// dummySecret384 / dummySecret512 are 48- and 64-char [A-Za-z0-9] values, the
// SECRET_LENGTH_384_BITS (HS384) and SECRET_LENGTH_512_BITS (HS512) secret
// lengths SecretGenerator also emits. They guard against regressing back to a
// 32-only pin, which would silently drop every HS384/HS512 client secret.
const dummySecret384 = dummySecret + "1cP4uK7iO2wA9zXb"                 // 32+16 = 48 chars
const dummySecret512 = dummySecret + "1cP4uK7iO2wA9zXbN5mV8qT3rY6eW0dL" // 32+32 = 64 chars

// lowEntropySecret is the false-positive shape the hardened detector now
// rejects: a 32-char run that clears the length+charset regex but has near-zero
// Shannon entropy (a padded placeholder), even when armed near the keyword.
const lowEntropySecret = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.KeyCloak {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("KEYCLOAK_CLIENT_ID=" + dummyID + "\nKEYCLOAK_CLIENT_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
	if string(res[0].RawV2) != dummySecret {
		t.Errorf("RawV2 mismatch: %s", res[0].RawV2)
	}
}

// TestFromData_HS384_HS512Lengths locks in recall for the 48- and 64-char
// secret lengths SecretGenerator emits for HS384/HS512 clients. A 32-only pin
// would silently drop these real secrets.
func TestFromData_HS384_HS512Lengths(t *testing.T) {
	for name, sec := range map[string]string{"HS384(48)": dummySecret384, "HS512(64)": dummySecret512} {
		body := []byte("KEYCLOAK_CLIENT_SECRET=" + sec)
		res, _ := Scanner{}.FromData(context.Background(), false, body)
		if len(res) == 0 {
			t.Fatalf("%s: expected >=1, got 0 (length-pin regression)", name)
		}
		if string(res[0].RawV2) != sec {
			t.Errorf("%s: RawV2 mismatch: %s", name, res[0].RawV2)
		}
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("CLIENT_ID=" + dummyID + "\nCLIENT_SECRET=" + dummySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// TestFromData_LowEntropyRejected pins the FP-hardening: a 32-char run that
// matches the length+charset regex AND sits next to a keycloak assignment
// keyword must NOT surface, because it fails the entropy floor.
func TestFromData_LowEntropyRejected(t *testing.T) {
	body := []byte("KEYCLOAK_CLIENT_SECRET=" + lowEntropySecret)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy secret rejected), got %d", len(res))
	}
}

func TestVerify_Disabled_Default(t *testing.T) {
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
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
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
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
	v, _ := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}
