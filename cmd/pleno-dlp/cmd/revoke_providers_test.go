package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/audit"
)

// TestRevoke_RegistryProviders_DryRunAuditTrail pins issue #809: each
// newly added Revoker resolves through the registry fallback, honours
// --dry-run without contacting the provider, and emits one audit record
// that never contains the raw secret.
func TestRevoke_RegistryProviders_DryRunAuditTrail(t *testing.T) {
	cases := map[string]string{
		"anthropic":         "Anthropic",
		"OpenAI":            "OpenAI",
		"gcpserviceaccount": "GCPServiceAccount",
		"huggingface":       "HuggingFace",
		"notion":            "Notion",
		"resend":            "Resend",
		"vercel":            "Vercel",
	}
	for flag, wantType := range cases {
		t.Run(wantType, func(t *testing.T) {
			resetCommandFlags(t)
			trail := filepath.Join(t.TempDir(), "trail.jsonl")
			secret := "dryrun-secret-" + wantType + "-0123456789abcdef"
			var out, errBuf bytes.Buffer
			Root.SetOut(&out)
			Root.SetErr(&errBuf)
			Root.SetArgs([]string{"revoke", "--detector", flag, "--secret", secret, "--dry-run", "--audit-trail", trail})
			if err := Root.Execute(); err != nil {
				t.Fatalf("revoke --dry-run: %v\n%s", err, errBuf.String())
			}
			rec := readSoleAuditRecordFile(t, trail)
			if rec.Detector != wantType || !rec.DryRun || rec.Revoked || rec.Path != string(audit.PathSingle) {
				t.Errorf("record = %+v", rec)
			}
			if rec.SecretHash != audit.HashSecret(secret) {
				t.Errorf("secret_hash mismatch")
			}
			body, _ := os.ReadFile(trail)
			if strings.Contains(string(body)+out.String()+errBuf.String(), secret) {
				t.Fatal("raw secret leaked")
			}
		})
	}
}

func TestRevoke_UnknownDetectorListsRegistryRevokers(t *testing.T) {
	resetCommandFlags(t)
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"revoke", "--detector", "jwt", "--secret", "x", "--dry-run"})
	err := Root.Execute()
	if err == nil {
		t.Fatal("jwt has no Revoker; want error")
	}
	for _, want := range []string{"anthropic", "vercel", "stripe"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should list %q", err, want)
		}
	}
}
