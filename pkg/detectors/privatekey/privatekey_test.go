package privatekey

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/privatekey/blastradius"
)

const rsaBlock = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
-----END RSA PRIVATE KEY-----`

const opensshBlock = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACBzZXJ2ZXIuYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==
-----END OPENSSH PRIVATE KEY-----`

const pkcs8Block = `-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKj3xMwwxxxxxxxx
-----END PRIVATE KEY-----`

// Minimal PGP armor fixture (valid structure; body is intentionally synthetic).
const pgpBlock = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQVYBGRkZGQBDAC5example+base64+content+here==
=ABCD
-----END PGP PRIVATE KEY BLOCK-----`

func TestFromData_RSA(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("preamble\n"+rsaBlock+"\nepilogue"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].ExtraData["algorithm"] != "RSA" {
		t.Fatalf("algorithm wrong: %+v", res[0].ExtraData)
	}
}

func TestFromData_OpenSSH(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(opensshBlock))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].ExtraData["algorithm"] != "OPENSSH" {
		t.Fatalf("algorithm wrong: %+v", res[0].ExtraData)
	}
}

func TestFromData_PGP(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte(pgpBlock))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d: PGP PRIVATE KEY BLOCK not detected", len(res))
	}
	if res[0].ExtraData["algorithm"] != "PGP" {
		t.Fatalf("algorithm wrong, want PGP: %+v", res[0].ExtraData)
	}
}

func TestFromData_PKCS8(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(pkcs8Block))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].ExtraData["algorithm"] != "PKCS8" {
		t.Fatalf("algorithm wrong: %+v", res[0].ExtraData)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("PRIVATE KEY but no markers"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(rsaBlock))
	if !strings.Contains(res[0].Redacted, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("redacted missing alg: %q", res[0].Redacted)
	}
	if strings.Contains(res[0].Redacted, "MIIE") {
		t.Fatalf("redacted leaked body: %q", res[0].Redacted)
	}
}

// freshRSA returns a parseable RSA-2048 PKCS#1 PEM block for tests
// that need the blastradius layer to extract a real fingerprint.
func freshRSA(t *testing.T) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

func TestFromData_PopulatesFingerprint(t *testing.T) {
	body := freshRSA(t)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	fp := res[0].ExtraData["pubkey_fingerprint_sha256"]
	if len(fp) != 64 {
		t.Errorf("fingerprint missing or malformed: %q", fp)
	}
	if res[0].ExtraData["pubkey_algorithm"] != "RSA" {
		t.Errorf("pubkey_algorithm = %q, want RSA", res[0].ExtraData["pubkey_algorithm"])
	}
}

func TestVerify_CTHit_ReturnsTrue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"id": 42, "common_name": "example.com", "name_value": "example.com\nwww.example.com"}]`))
	}))
	defer srv.Close()
	s := Scanner{CT: &blastradius.CTClient{BaseURL: srv.URL, HTTPClient: srv.Client()}}
	verified, err := s.Verify(context.Background(), string(freshRSA(t)))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !verified {
		t.Errorf("expected verified=true on CT hit")
	}
}

func TestVerify_CTMiss_ReturnsFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	s := Scanner{CT: &blastradius.CTClient{BaseURL: srv.URL, HTTPClient: srv.Client()}}
	verified, err := s.Verify(context.Background(), string(freshRSA(t)))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified {
		t.Errorf("expected verified=false on empty CT result")
	}
}

func TestVerify_TransportError_Surfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	s := Scanner{CT: &blastradius.CTClient{BaseURL: srv.URL, HTTPClient: srv.Client()}}
	verified, err := s.Verify(context.Background(), string(freshRSA(t)))
	if err == nil {
		t.Errorf("expected transport error to surface")
	}
	if verified {
		t.Errorf("verified should be false on transport error, got true")
	}
}

func TestFromData_EncryptedFlag(t *testing.T) {
	body := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("dummy ciphertext"),
	})
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if res[0].ExtraData["pem_encrypted"] != "true" {
		t.Errorf("expected pem_encrypted=true, got %q", res[0].ExtraData["pem_encrypted"])
	}
	if _, ok := res[0].ExtraData["pem_unlocked_with"]; ok {
		t.Errorf("pem_unlocked_with should be absent for unbreakable ciphertext")
	}
}

// Static interface conformance.
var (
	_ detectors.Detector = Scanner{}
	_ detectors.Verifier = Scanner{}
)

func TestFromData_VerifyPropagatesBlastRadius(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
		  {"id": 1, "common_name": "example.com", "name_value": "example.com\nwww.example.com"},
		  {"id": 2, "common_name": "api.example.com", "name_value": "api.example.com"}
		]`))
	}))
	defer srv.Close()
	s := Scanner{CT: &blastradius.CTClient{BaseURL: srv.URL, HTTPClient: srv.Client()}}
	res, err := s.FromData(context.Background(), true, freshRSA(t))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1, got %d", len(res))
	}
	r := res[0]
	if !r.Verified {
		t.Errorf("expected Verified=true on CT match")
	}
	if r.ExtraData["ct_status"] != "match" {
		t.Errorf("ct_status = %q, want match", r.ExtraData["ct_status"])
	}
	if r.ExtraData["blast_radius_cert_count"] != "2" {
		t.Errorf("cert_count = %q, want 2", r.ExtraData["blast_radius_cert_count"])
	}
	domains := r.ExtraData["blast_radius_domains"]
	for _, d := range []string{"example.com", "www.example.com", "api.example.com"} {
		if !strings.Contains(domains, d) {
			t.Errorf("domains %q missing %q", domains, d)
		}
	}
}

func TestFromData_VerifyNoMatch_NoVerifiedFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	s := Scanner{CT: &blastradius.CTClient{BaseURL: srv.URL, HTTPClient: srv.Client()}}
	res, err := s.FromData(context.Background(), true, freshRSA(t))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res[0].Verified {
		t.Errorf("Verified should be false on empty CT match")
	}
	if res[0].ExtraData["ct_status"] != "no-match" {
		t.Errorf("ct_status = %q, want no-match", res[0].ExtraData["ct_status"])
	}
	if _, ok := res[0].ExtraData["blast_radius_domains"]; ok {
		t.Errorf("blast_radius_domains must be absent on no-match")
	}
}
