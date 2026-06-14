//go:build detector_unit

package kubeconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const sample = `apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster:
    server: https://k8s.example.com
contexts:
- name: prod
  context:
    cluster: prod
    user: admin
users:
- name: admin
  user:
    client-certificate-data: ` + "TUlJRmFEQ0NBMUNnQXdJQkFnSVVMSDhIZUFRb1F4Z3lJM3o1ZGdLNlVQVnZGM3d3RFFZSktvWklodmNO" + `
    client-key-data: ` + "TUlJRXZRSUJBREFOQmdrcWhraUc5dzBCQVFFRkFBU0NCS2N3Z2dTakFnRUFBb0lCQVFEUjdGV2VmYU01" + `
- name: bot
  user:
    token: ` + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzIn0.AbCdEfGhIj"

func TestFromData_AllThreeFields(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(sample))
	if len(res) != 3 {
		t.Fatalf("expected 3 (cert, key, token), got %d", len(res))
	}
	fields := map[string]bool{}
	for _, r := range res {
		fields[r.ExtraData["field"]] = true
		if r.Severity != detectors.SeverityCritical {
			t.Fatalf("severity for %s: %v", r.ExtraData["field"], r.Severity)
		}
	}
	for _, want := range []string{"client-certificate-data", "client-key-data", "token"} {
		if !fields[want] {
			t.Fatalf("missing field %q in results", want)
		}
	}
}

func TestFromData_NotKubeconfig(t *testing.T) {
	// Bare `token:` line without kind: Config is not a kubeconfig leak.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("token: abcdefghijklmnopqrstu"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_UserNameCapture(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(sample))
	for _, r := range res {
		if r.ExtraData["field"] != "token" {
			continue
		}
		if got := r.ExtraData["user_name"]; got != "bot" {
			t.Fatalf("expected user_name=bot, got %q", got)
		}
		if string(r.RawV2) != "bot" {
			t.Fatalf("rawv2: %q", r.RawV2)
		}
	}
	// Defensive: make sure we didn't accidentally leak the raw secret
	// into the redact path.
	for _, r := range res {
		if strings.Contains(r.Redacted, string(r.Raw)) {
			t.Fatal("redacted should not contain raw secret in full")
		}
	}
}

// ---- Semantic-hardening fixtures ----------------------------------------

// FP1: multi-document YAML where a kustomize-style `kind: Config` object
// coexists with an unrelated app section carrying a placeholder token.
// The placeholder is NOT under a users: block and is a literal fill, so
// both the vicinity guard and the placeholder guard suppress it.
const fpMultiDoc = `apiVersion: kustomize.config.k8s.io/v1beta1
kind: Config
resources:
- deployment.yaml
---
apiVersion: apps/v1
kind: Deployment
spec:
  env:
    token: changeme-rotate-this-now
`

// FP2: Helm values file with a `kind: Config` object plus a webhook block
// whose `token:` is a low-entropy, non-credential descriptor. Not under a
// users: block, low entropy, and a placeholder hint.
const fpHelmValues = `apiVersion: v1
kind: Config
metadata:
  name: chart-defaults
webhook:
  token: github-actions-workflow-dispatch-trigger
`

// FP3: documentation/example YAML with a literal placeholder bearer token.
const fpDocExample = `apiVersion: v1
kind: Config
users:
- name: example
  user:
    token: your-bearer-token-here-please-replace
`

func TestFromData_SuppressesFalsePositives(t *testing.T) {
	for name, fixture := range map[string]string{
		"multi-doc kustomize placeholder": fpMultiDoc,
		"helm values webhook descriptor":  fpHelmValues,
		"doc example placeholder token":   fpDocExample,
	} {
		res, _ := Scanner{}.FromData(context.Background(), false, []byte(fixture))
		if len(res) != 0 {
			t.Errorf("%s: expected 0 findings, got %d (%q)", name, len(res), res[0].Raw)
		}
	}
}

// TP via exec-credential apiVersion: a real kubeconfig whose apiVersion is
// the client.authentication.k8s.io group, with a genuine high-entropy
// bearer token under a users: block. Still detected.
const tpExecAuth = `apiVersion: v1
kind: Config
clusters:
- name: staging
  cluster:
    server: https://10.0.0.1:6443
users:
- name: deployer
  user:
    token: ` + "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik1xN1pBcVQ4In0.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.Zx9QwErTyUiOpAsDfGhJkLzXcVbNm123"

func TestFromData_StillDetectsRealToken(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(tpExecAuth))
	if len(res) != 1 {
		t.Fatalf("expected 1 token finding, got %d", len(res))
	}
	if res[0].ExtraData["field"] != "token" {
		t.Fatalf("field: %q", res[0].ExtraData["field"])
	}
	if res[0].ExtraData["user_name"] != "deployer" {
		t.Fatalf("user_name: %q", res[0].ExtraData["user_name"])
	}
}

// Guard: a kubeconfig-shaped file missing the apiVersion line does not fire.
func TestFromData_RequiresApiVersion(t *testing.T) {
	noApiVersion := `kind: Config
users:
- name: admin
  user:
    token: ` + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzIn0.AbCdEfGhIj"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(noApiVersion))
	if len(res) != 0 {
		t.Fatalf("expected 0 without apiVersion, got %d", len(res))
	}
}

// ---- Server URL extraction tests ----------------------------------------

func TestExtractServers(t *testing.T) {
	doc := `apiVersion: v1
kind: Config
clusters:
- name: prod
  cluster:
    server: https://k8s.example.com:6443
    certificate-authority-data: LS0tLS1CRUdJTi...
- name: staging
  cluster:
    server: https://10.0.0.1:6443
`
	servers := extractServers(doc)
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}
	if servers[0].url != "https://k8s.example.com:6443" {
		t.Fatalf("server[0]: %q", servers[0].url)
	}
	if servers[1].url != "https://10.0.0.1:6443" {
		t.Fatalf("server[1]: %q", servers[1].url)
	}
	// Positions should be ordered.
	if servers[0].pos >= servers[1].pos {
		t.Fatalf("servers should be in document order: pos[0]=%d >= pos[1]=%d",
			servers[0].pos, servers[1].pos)
	}
}

func TestExtractServers_HTTP(t *testing.T) {
	doc := `clusters:
- cluster:
    server: http://localhost:8080
`
	servers := extractServers(doc)
	if len(servers) != 1 {
		t.Fatalf("expected 1, got %d", len(servers))
	}
	if servers[0].url != "http://localhost:8080" {
		t.Fatalf("server: %q", servers[0].url)
	}
}

func TestExtractServers_None(t *testing.T) {
	doc := `apiVersion: v1
kind: Config
users:
- name: admin
  user:
    token: abc123
`
	servers := extractServers(doc)
	if len(servers) != 0 {
		t.Fatalf("expected 0, got %d", len(servers))
	}
}

func TestFromData_ServerExtraData(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(sample))
	for _, r := range res {
		srv := r.ExtraData["server"]
		if srv != "https://k8s.example.com" {
			t.Errorf("field %s: expected server=https://k8s.example.com, got %q",
				r.ExtraData["field"], srv)
		}
	}
}

func TestFromData_ServerExtraData_MultiCluster(t *testing.T) {
	doc := `apiVersion: v1
kind: Config
clusters:
- name: alpha
  cluster:
    server: https://alpha.example.com:6443
- name: beta
  cluster:
    server: https://beta.example.com:6443
users:
- name: admin
  user:
    token: ` + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzIn0.AbCdEfGhIj"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(doc))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	// The token appears after both servers; nearest-before is beta.
	srv := res[0].ExtraData["server"]
	if srv != "https://beta.example.com:6443" {
		t.Fatalf("expected nearest server https://beta.example.com:6443, got %q", srv)
	}
}

// ---- Verify tests -------------------------------------------------------

func TestVerifyToken_200(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"major": "1", "minor": "28",
		})
	}))
	defer ts.Close()

	verified, err := verifyToken(context.Background(), ts.URL, "test-token-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Fatal("expected verified=true")
	}
}

func TestVerifyToken_401(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	verified, err := verifyToken(context.Background(), ts.URL, "bad-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false for 401")
	}
}

func TestVerifyToken_ConnectionRefused(t *testing.T) {
	// Point at a port that nothing listens on.
	verified, err := verifyToken(context.Background(), "https://127.0.0.1:1", "tok")
	if err != nil {
		t.Fatalf("connection errors should not be scan errors: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false for connection refused")
	}
}

func TestVerify_StandaloneToken(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer my-sa-token" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	verified, err := Scanner{}.Verify(context.Background(), ts.URL+"|my-sa-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_StandaloneBadFormat(t *testing.T) {
	// No pipe separator — should return false, nil.
	verified, err := Scanner{}.Verify(context.Background(), "just-a-token-no-pipe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false for bad format")
	}
}

// ---- Inline verify in FromData ------------------------------------------

func TestFromData_InlineVerifyToken(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"major":"1","minor":"28"}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	doc := `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: ` + ts.URL + `
users:
- name: svc
  user:
    token: ` + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzIn0.AbCdEfGhIj"

	res, err := Scanner{}.FromData(context.Background(), true, []byte(doc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatalf("expected Verified=true, got false (err=%v)", res[0].VerificationErr)
	}
}

func TestFromData_InlineVerifyToken_401(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	doc := `apiVersion: v1
kind: Config
clusters:
- name: test
  cluster:
    server: ` + ts.URL + `
users:
- name: svc
  user:
    token: ` + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzIn0.AbCdEfGhIj"

	res, err := Scanner{}.FromData(context.Background(), true, []byte(doc))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("expected Verified=false for 401")
	}
}

// ---- mTLS verify tests --------------------------------------------------

// generateTestCertKeyPair creates a self-signed cert+key pair and returns
// them as base64-encoded PEM strings suitable for kubeconfig YAML.
func generateTestCertKeyPair(t *testing.T) (certB64, keyB64 string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return base64.StdEncoding.EncodeToString(certPEM),
		base64.StdEncoding.EncodeToString(keyPEM)
}

func TestVerifyMTLS_200(t *testing.T) {
	certB64, keyB64 := generateTestCertKeyPair(t)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept any TLS client that connects (InsecureSkipVerify on our side too).
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"major":"1","minor":"28"}`))
	}))
	defer ts.Close()

	verified, err := verifyMTLS(context.Background(), ts.URL, certB64, keyB64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Fatal("expected verified=true")
	}
}

func TestVerifyMTLS_BadCert(t *testing.T) {
	// Invalid base64 for cert — should return false, nil.
	verified, err := verifyMTLS(context.Background(), "https://127.0.0.1:1", "!!!bad!!!", "!!!bad!!!")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false for bad cert")
	}
}

func TestVerify_StandaloneMTLS(t *testing.T) {
	certB64, keyB64 := generateTestCertKeyPair(t)

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	secret := ts.URL + "|" + certB64 + "|" + keyB64
	verified, err := Scanner{}.Verify(context.Background(), secret)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Fatal("expected verified=true")
	}
}
