package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigInitThenScanWithConfig(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "pleno-dlp.yaml")
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"config", "init", "--format", "json", "--fail-on=critical", "--no-verify",
		"--exclude-detectors", "github,gitlab", "--extraction-depth", "5", "--out", cfgPath})
	if err := Root.Execute(); err != nil {
		t.Fatalf("config init: %v", err)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"version: 1", "format: json", "fail-on: critical", "no-verify: \"true\"", "- github", "- gitlab", "extraction-depth: \"5\""} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("config missing %q:\n%s", want, raw)
		}
	}
	if strings.Contains(string(raw), "concurrency") {
		t.Fatalf("defaults leaked into config:\n%s", raw)
	}
	// Refuses to overwrite without --force.
	resetCommandFlags(t)
	Root.SetArgs([]string{"config", "init", "--format", "sarif", "--out", cfgPath})
	if err := Root.Execute(); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("want overwrite refusal, got %v", err)
	}

	resetCommandFlags(t)
	target := t.TempDir()
	if err := os.WriteFile(filepath.Join(target, "a.env"), []byte("AWS_ACCESS_KEY_ID="+alertFixtureKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	var stderr bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&stderr)
	Root.SetArgs([]string{"scan", "filesystem", target, "--quiet", "--config", cfgPath})
	if err := Root.Execute(); err != nil {
		t.Fatalf("scan: %v\n%s", err, stderr.String())
	}
	if scanOpts.format != "json" || scanOpts.extractionDepth != 5 || !scanOpts.noVerify {
		t.Fatalf("config not applied: %+v", scanOpts)
	}
	if !strings.HasPrefix(strings.TrimSpace(out.String()), "[") && !strings.HasPrefix(strings.TrimSpace(out.String()), "{") {
		t.Fatalf("expected JSON output, got %q", out.String())
	}

	// CLI scalar wins; lists are additive.
	resetCommandFlags(t)
	Root.SetArgs([]string{"scan", "filesystem", target, "--quiet", "--config", cfgPath, "--format", "jsonl", "--exclude-detectors", "stripe"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if scanOpts.format != "jsonl" {
		t.Fatalf("CLI scalar lost: %q", scanOpts.format)
	}
	if got := strings.Join(scanOpts.excludeDetectors, ","); got != "stripe,github,gitlab" {
		t.Fatalf("lists not additive: %q", got)
	}
}

func TestConfigRejectsUnknownAndSecretKeys(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"unknown":    "version: 1\nscan:\n  no-such-flag: 1\n",
		"credential": "version: 1\nscan:\n  git-" + "token: x\n", // pleno-dlp:allow test fixture
		"version":    "version: 2\nscan: {}\n",
		"toplevel":   "version: 1\nbogus: 1\n",
		"list":       "version: 1\nscan:\n  format: [json, sarif]\n",
	} {
		t.Run(name, func(t *testing.T) {
			resetCommandFlags(t)
			p := filepath.Join(dir, name+".yaml")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			Root.SetArgs([]string{"scan", "filesystem", dir, "--config", p})
			if err := Root.Execute(); err == nil || !strings.Contains(err.Error(), "--config") {
				t.Fatalf("want --config error, got %v", err)
			}
		})
	}
	resetCommandFlags(t)
	Root.SetArgs([]string{"config", "init", "--git-token", "x"})
	if err := Root.Execute(); err == nil {
		t.Fatal("config init accepted a credential flag")
	}
}
