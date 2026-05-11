package blastradius

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// rsaPEM constructs a fresh RSA-2048 PKCS#1 PEM block for tests so we
// do not need to ship a real private key in the repo.
func rsaPEM(t *testing.T) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
}

// ecPEM constructs a fresh P-256 EC PKCS#1-flavoured PEM block.
func ecPEM(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec gen: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatalf("ec marshal: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// pkcs8Ed25519PEM constructs a fresh Ed25519 key wrapped in PKCS#8.
func pkcs8Ed25519PEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 gen: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("pkcs8 marshal: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestDerive_RSA(t *testing.T) {
	pk, err := Derive(rsaPEM(t))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if pk.Algorithm != "RSA" {
		t.Errorf("alg = %q, want RSA", pk.Algorithm)
	}
	if len(pk.SPKISHA256Hex) != 64 {
		t.Errorf("fingerprint len = %d, want 64", len(pk.SPKISHA256Hex))
	}
}

func TestDerive_EC(t *testing.T) {
	pk, err := Derive(ecPEM(t))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if pk.Algorithm != "EC" {
		t.Errorf("alg = %q, want EC", pk.Algorithm)
	}
	if len(pk.SPKISHA256Hex) != 64 {
		t.Errorf("fingerprint len = %d, want 64", len(pk.SPKISHA256Hex))
	}
}

func TestDerive_PKCS8Ed25519(t *testing.T) {
	pk, err := Derive(pkcs8Ed25519PEM(t))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if pk.Algorithm != "ED25519" {
		t.Errorf("alg = %q, want ED25519", pk.Algorithm)
	}
}

func TestDerive_NoBlock(t *testing.T) {
	_, err := Derive([]byte("not a pem"))
	if !errors.Is(err, ErrNoPEMBlock) {
		t.Errorf("err = %v, want ErrNoPEMBlock", err)
	}
}

func TestDerive_LeadingProse(t *testing.T) {
	body := append([]byte("free-form text before the key\n\n"), rsaPEM(t)...)
	pk, err := Derive(body)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if pk.SPKISHA256Hex == "" {
		t.Errorf("expected fingerprint with leading prose")
	}
}

func TestDerive_DeterministicFingerprint(t *testing.T) {
	body := rsaPEM(t)
	a, _ := Derive(body)
	b, _ := Derive(body)
	if a.SPKISHA256Hex != b.SPKISHA256Hex {
		t.Errorf("fingerprint not deterministic: %q != %q", a.SPKISHA256Hex, b.SPKISHA256Hex)
	}
}

func TestDerive_EncryptedShortCircuits(t *testing.T) {
	encryptedBody := pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: []byte("not real ciphertext"),
	})
	_, err := Derive(encryptedBody)
	if !errors.Is(err, ErrEncrypted) {
		t.Errorf("err = %v, want ErrEncrypted", err)
	}
}

func TestDefaultPassphrases_NonEmpty(t *testing.T) {
	pw := DefaultPassphrases()
	if len(pw) < 100 {
		t.Errorf("wordlist too small: %d", len(pw))
	}
	if pw[len(pw)-1] != "" {
		t.Errorf("last entry should be \"\" fallback, got %q", pw[len(pw)-1])
	}
}

func TestTryDecrypt_NoMatch(t *testing.T) {
	encrypted := &pem.Block{
		Type: "RSA PRIVATE KEY",
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  "AES-128-CBC,00000000000000000000000000000000",
		},
		Bytes: []byte("garbage ciphertext that no key will ever decrypt"),
	}
	body := pem.EncodeToMemory(encrypted)
	_, _, err := TryDecrypt(body, []string{"a", "b", "c"})
	if !errors.Is(err, ErrNoPassphraseMatch) {
		t.Errorf("err = %v, want ErrNoPassphraseMatch", err)
	}
}

func TestCTClient_Lookup_NoMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("spkisha256") == "" {
			t.Errorf("missing spkisha256 query")
		}
		if r.URL.Query().Get("output") != "json" {
			t.Errorf("missing output=json")
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	c := &CTClient{BaseURL: srv.URL, HTTPClient: srv.Client()}
	matches, err := c.Lookup(context.Background(), strings.Repeat("a", 64))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("got %d matches, want 0", len(matches))
	}
}

func TestCTClient_Lookup_Domains(t *testing.T) {
	body := `[
	  {"id": 100, "common_name": "example.com", "name_value": "example.com\nwww.example.com"},
	  {"id": 200, "common_name": "api.example.com", "name_value": "api.example.com\n*.example.com"}
	]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	c := &CTClient{BaseURL: srv.URL, HTTPClient: srv.Client()}
	matches, err := c.Lookup(context.Background(), strings.Repeat("0", 64))
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("got %d, want 2", len(matches))
	}
	domains := Domains(matches)
	want := map[string]bool{
		"example.com":     true,
		"www.example.com": true,
		"api.example.com": true,
		"*.example.com":   true,
	}
	if len(domains) != len(want) {
		t.Errorf("domains = %v, want %v", domains, want)
	}
	for _, d := range domains {
		if !want[d] {
			t.Errorf("unexpected domain %q", d)
		}
	}
}

func TestCTClient_Lookup_BadFingerprint(t *testing.T) {
	c := NewCTClient()
	_, err := c.Lookup(context.Background(), "not-hex")
	if err == nil {
		t.Errorf("expected error for invalid fingerprint")
	}
}

func TestCTClient_Lookup_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream busy"))
	}))
	defer srv.Close()
	c := &CTClient{BaseURL: srv.URL, HTTPClient: srv.Client()}
	_, err := c.Lookup(context.Background(), strings.Repeat("0", 64))
	if err == nil {
		t.Errorf("expected error on 502")
	}
}

func TestCTClient_RespectsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	c := &CTClient{BaseURL: srv.URL, HTTPClient: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.Lookup(ctx, strings.Repeat("0", 64))
	if err == nil {
		t.Errorf("expected timeout error")
	}
}

func TestSplitSANs(t *testing.T) {
	got := splitSANs("a.example.com\nb.example.com\n\nc.example.com")
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] %q != %q", i, got[i], want[i])
		}
	}
}

func TestIsHex64(t *testing.T) {
	cases := map[string]bool{
		strings.Repeat("a", 64): true,
		strings.Repeat("0", 64): true,
		strings.Repeat("a", 63): false,
		strings.Repeat("a", 65): false,
		strings.Repeat("g", 64): false,
		strings.Repeat("A", 64): false, // uppercase rejected — crt.sh expects lowercase
	}
	for in, want := range cases {
		if got := isHex64(in); got != want {
			t.Errorf("isHex64(%q) = %v, want %v", in[:8]+"...", got, want)
		}
	}
}
