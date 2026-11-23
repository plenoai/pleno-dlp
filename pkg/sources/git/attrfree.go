package git

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// attrFreeDir is a temporary git directory that borrows the repository's
// object store through objects/info/alternates but has no info/attributes.
// Merge resolutions render as dense combined diffs, which ignore --text, so
// attribute-binary text can only be forced through by clearing every
// attribute source: --attr-source covers the tree, core.attributesFile and
// GIT_ATTR_NOSYSTEM the global and system files, and this directory the
// repository-local $GIT_DIR/info/attributes (#998).
type attrFreeDir struct {
	once sync.Once
	dir  string
	err  error
}

func (s *Source) attrFreeGitDir(ctx context.Context, gitBin string) (string, error) {
	a := s.attrFree
	if a == nil {
		return "", errors.New("git: attribute-free git directory used outside a walk")
	}
	a.once.Do(func() { a.dir, a.err = createAttrFreeDir(ctx, gitBin, s.repoAbs) })
	return a.dir, a.err
}

func createAttrFreeDir(ctx context.Context, gitBin, repoAbs string) (string, error) {
	cmd := exec.CommandContext(ctx, gitBin, "-C", repoAbs, "rev-parse", "--path-format=absolute", "--git-common-dir")
	cmd.Env = nativeGitEnv()
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git: locate common dir for attribute-free rendering: %w", err)
	}
	common := strings.TrimRight(string(out), "\r\n")
	objects := filepath.Join(common, "objects")
	if strings.ContainsAny(objects, "\n") {
		return "", fmt.Errorf("git: object directory %q cannot be an alternate", objects)
	}
	dir, err := os.MkdirTemp("", "pleno-dlp-attrfree-*")
	if err != nil {
		return "", fmt.Errorf("git: create attribute-free git directory: %w", err)
	}
	files := map[string]string{
		"HEAD":                    "ref: refs/heads/pleno-dlp\n",
		"config":                  "[core]\n\trepositoryformatversion = 0\n\tbare = true\n",
		"objects/info/alternates": objects + "\n",
	}
	for _, sub := range []string{"refs", "objects/info"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("git: create attribute-free git directory: %w", err)
		}
	}
	// A shallow repository's grafted boundary must stay visible, or git
	// would chase the missing parents of boundary commits.
	if shallow, err := os.ReadFile(filepath.Join(common, "shallow")); err == nil {
		files["shallow"] = string(shallow)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			_ = os.RemoveAll(dir)
			return "", fmt.Errorf("git: create attribute-free git directory: %w", err)
		}
	}
	return dir, nil
}

func (a *attrFreeDir) cleanup() {
	if a != nil && a.dir != "" {
		_ = os.RemoveAll(a.dir)
	}
}
