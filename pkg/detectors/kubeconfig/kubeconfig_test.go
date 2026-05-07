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
