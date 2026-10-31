package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFeedbackPIIAutoDoesNotTreatUVAloneAsAvailable(t *testing.T) {
	resetCommandFlags(t)
	cacheDir := t.TempDir()
	t.Setenv("PLENO_DLP_ANONYMIZE_CACHE", cacheDir)
	marker := filepath.Join(t.TempDir(), "uv-started")
	uvPath := filepath.Join(t.TempDir(), "uv")
	if err := os.WriteFile(uvPath, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	prevUV := uvBin
	uvBin = uvPath
	t.Cleanup(func() { uvBin = prevUV })

	selection, err := selectFeedbackPII(context.Background())
	if err != nil {
		t.Fatalf("selectFeedbackPII: %v", err)
	}
	if selection.Detector != nil || selection.Stop != nil {
		t.Fatalf("selection = %+v, want no PII engine", selection)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("UV ran without a cached runtime: stat marker err = %v", err)
	}
}

func TestCachedAnonymizeRuntimeRequiresInstalledEnvironment(t *testing.T) {
	dir := t.TempDir()
	uvPath := filepath.Join(dir, "uv")
	if err := os.WriteFile(uvPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(dir, "cache")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	if cachedAnonymizeRuntimeAvailable(uvPath, cache) {
		t.Fatal("UV plus an empty cache must not count as an available engine")
	}

	for _, d := range []string{".git", ".venv", filepath.Join("server", "src")} {
		if err := os.MkdirAll(filepath.Join(cache, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{
		"pyproject.toml",
		"uv.lock",
		filepath.Join(".venv", "pyvenv.cfg"),
		filepath.Join("server", "src", "app.py"),
	} {
		if err := os.WriteFile(filepath.Join(cache, file), []byte("local fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sitePackages := filepath.Join(cache, ".venv", "lib", "python3.12", "site-packages")
	for _, model := range []string{"spacy", "en_core_web_sm", "pleno_anonymize_ja", "pleno_anonymize_en"} {
		if err := os.MkdirAll(filepath.Join(sitePackages, model), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if !cachedAnonymizeRuntimeAvailable(uvPath, cache) {
		t.Fatal("a pinned local runtime with all NER model packages should be available")
	}
	argv := strings.Join(cachedAnonymizeArgv(uvPath, cache), " ")
	if !strings.Contains(argv, "--offline") || !strings.Contains(argv, "--no-sync") {
		t.Fatalf("cached startup argv can access network or install dependencies: %s", argv)
	}
	env := strings.Join(cachedAnonymizeEnv(), ",")
	for _, required := range []string{"HF_HUB_OFFLINE=1", "TRANSFORMERS_OFFLINE=1"} {
		if !strings.Contains(env, required) {
			t.Fatalf("cached startup environment lacks %s: %s", required, env)
		}
	}
}

func TestAnonymizeCachePinProbeUsesLocalGitOnly(t *testing.T) {
	dir := t.TempDir()
	gitPath := filepath.Join(dir, "git")
	calls := filepath.Join(dir, "git-calls")
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$CALLS\"\n" +
		"if [ \"$3\" = rev-parse ] && [ \"$4\" = --verify ] && [ \"$5\" = HEAD ]; then echo \"$PINNED\"; exit 0; fi\n" +
		"exit 1\n"
	if err := os.WriteFile(gitPath, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CALLS", calls)
	t.Setenv("PINNED", defaultPIIServerCommit)
	prevGit := gitBin
	gitBin = gitPath
	t.Cleanup(func() { gitBin = prevGit })

	if !isPinnedPIIServerCache(dir) {
		t.Fatal("cache at the pinned commit was rejected")
	}
	log, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(log), "fetch") || strings.Contains(string(log), "clone") {
		t.Fatalf("offline cache probe used network git command: %q", log)
	}
	t.Setenv("PINNED", "other-commit")
	if isPinnedPIIServerCache(dir) {
		t.Fatal("cache at a different commit was accepted")
	}
}
