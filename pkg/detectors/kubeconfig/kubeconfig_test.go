package kubeconfig

import (
	"context"
	"strings"
	"testing"

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
