package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// pinnedVersion documents the version this harness was validated
// against. It is informational only — the harness runs whatever binary
// it resolves and reports the *actual* `--version` output in
// results.md, so a locally installed newer/older build is visible in
// the output rather than silently misreported as the pin. Bumping a pin
// is a deliberate, reviewable diff (see bench/CONTRIBUTING.md);
// bench/scripts/fetch-tools.sh downloads exactly these versions with a
// pinned checksum for anyone without a local install (CI's path).
var pinnedVersion = map[string]string{
	"trufflehog": "3.95.5",
	"gitleaks":   "8.30.1",
}

// resolveBinary finds tool's executable: explicit override (the
// -pleno-dlp-bin/-trufflehog-bin/-gitleaks-bin flags) first, then
// bench/.tools/<name> (bench/scripts/fetch-tools.sh's install
// location), then $PATH. Returns an error naming the exact fix instead
// of a bare "not found" — a third party's first run should never dead-end.
func resolveBinary(override, name, fetchHint string) (string, error) {
	if override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", fmt.Errorf("resolveBinary(%s): explicit path %q: %w", name, override, err)
		}
		return override, nil
	}
	local := "bench/.tools/" + name
	if _, err := os.Stat(local); err == nil {
		return local, nil
	}
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	return "", fmt.Errorf(
		"%s not found on $PATH or at %s — run `%s` (or `make bench-tools`) first",
		name, local, fetchHint,
	)
}

// toolVersion shells out to `<bin> --version` (gitleaks) or
// `<bin> --version` (trufflehog also supports this) and returns the
// trimmed first line. Best-effort: a failure just leaves the results
// table's version column blank rather than aborting the whole run.
func toolVersion(bin string) string {
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	s := string(out)
	for i, c := range s {
		if c == '\n' {
			s = s[:i]
			break
		}
	}
	return s
}

// warnIfVersionDrifted prints a one-line stderr notice when the
// resolved binary's version string doesn't contain the pin from
// pinnedVersion — e.g. a locally-installed trufflehog newer than what
// bench/scripts/fetch-tools.sh downloads. Non-fatal: results.md still
// reports the actual version, so a drifted run is visible, not hidden,
// but doesn't block `make bench` for someone testing against a newer
// release on purpose.
func warnIfVersionDrifted(name, actualVersion string) {
	pin, ok := pinnedVersion[filepath.Base(name)]
	if !ok || actualVersion == "" {
		return
	}
	if !strings.Contains(actualVersion, pin) {
		fmt.Fprintf(os.Stderr, "harness: warning: %s reports %q, pinned version is %s (see bench/CONTRIBUTING.md to bump the pin)\n", name, actualVersion, pin)
	}
}
