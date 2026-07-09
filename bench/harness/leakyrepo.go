package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// leakyRepoURL and leakyRepoCommit pin the real-world recall corpus
// used by docs/comparison.md §3: Plazmaz/leaky-repo, the
// community-standard scanner benchmark. Pinning the commit (not just
// the branch) is what makes this reproducible — see bench/README.md.
const (
	leakyRepoURL    = "https://github.com/Plazmaz/leaky-repo.git"
	leakyRepoCommit = "2e951359cac53addbee56437da3ffb546e3dfe24"
)

// ensureLeakyRepo clones leakyRepoURL into dir at leakyRepoCommit if dir
// doesn't already exist, then strips .git — trufflehog's filesystem
// source reads .git internals directly (decompresses loose objects),
// which would make its finding count incomparable to pleno-dlp's and
// gitleaks' worktree-only dir scans; see docs/comparison.md §7's
// documented reason every corpus here is ".git-free unless the probe
// says otherwise".
func ensureLeakyRepo(dir string) error {
	if _, err := os.Stat(dir); err == nil {
		return nil // reuse: caller passed an existing checkout (e.g. CI cache)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return fmt.Errorf("ensureLeakyRepo: %w", err)
	}
	clone := exec.Command("git", "clone", "--quiet", leakyRepoURL, dir)
	if out, err := clone.CombinedOutput(); err != nil {
		return fmt.Errorf("ensureLeakyRepo: git clone: %w: %s", err, out)
	}
	checkout := exec.Command("git", "-C", dir, "checkout", "--quiet", leakyRepoCommit)
	if out, err := checkout.CombinedOutput(); err != nil {
		return fmt.Errorf("ensureLeakyRepo: git checkout %s: %w: %s", leakyRepoCommit, err, out)
	}
	if err := os.RemoveAll(filepath.Join(dir, ".git")); err != nil {
		return fmt.Errorf("ensureLeakyRepo: strip .git: %w", err)
	}
	return nil
}

// parseLeakyRepoGroundTruth reads leaky-repo's own
// .leaky-meta/secrets.csv — upstream's ground-truth inventory of every
// file it deliberately seeded with a secret or sensitive artifact — so
// the harness never has to author or maintain its own real-world label
// file (which this project could not adversarially audit as
// confidently as upstream's own accounting). Every non-comment,
// non-blank line counts as a ground-truth file regardless of its
// risk/informative split: docs/comparison.md §3's "44 ground-truth
// files" is exactly len(secrets.csv)'s data rows, not just the
// risk>0 subset (42 of the 44) — informative-only files like
// .ssh/id_rsa.pub still name a real artifact a scanner should ideally
// flag.
func parseLeakyRepoGroundTruth(repoDir string) ([]string, error) {
	path := filepath.Join(repoDir, ".leaky-meta", "secrets.csv")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("parseLeakyRepoGroundTruth: %w", err)
	}
	defer f.Close()

	var files []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 1 || fields[0] == "" {
			continue
		}
		files = append(files, fields[0])
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parseLeakyRepoGroundTruth: %w", err)
	}
	return files, nil
}
