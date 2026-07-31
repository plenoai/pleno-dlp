package git

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-billy/v5/osfs"
	git "github.com/go-git/go-git/v5"
	gogitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/storage"
	gogitfs "github.com/go-git/go-git/v5/storage/filesystem"
)

// openRepo opens a git repository from path. It handles repos with
// extensions.worktreeConfig=true which go-git v5 rejects via a false negative:
// go-git lowercases extension keys before comparison but the allowlist maps use
// camelCase ("worktreeConfig"), so the lowercase key "worktreeconfig" is never
// found. Since go-git does not implement worktreeConfig semantics regardless,
// stripping the extension from the in-memory config view is safe for the
// read-only scan operations pleno-dlp performs.
func openRepo(path string) (*git.Repository, error) {
	repo, err := git.PlainOpen(path)
	if err == nil {
		return repo, nil
	}
	if !errors.Is(err, git.ErrUnknownExtension) &&
		!errors.Is(err, git.ErrUnsupportedExtensionRepositoryFormatVersion) {
		return nil, err
	}
	return openRepoStrippingExtensions(path, err)
}

// openRepoStrippingExtensions retries PlainOpen using a storer that removes
// extensions go-git falsely rejects due to key-casing bugs. originalErr is
// returned on any secondary failure so the caller sees the root cause.
func openRepoStrippingExtensions(path string, originalErr error) (*git.Repository, error) {
	// Resolve the .git directory: standard repo has a .git dir; a bare repo or
	// linked worktree may have the git dir directly at path or via a .git file.
	dotGit, worktreePath, err := resolveDotGit(path)
	if err != nil {
		return nil, originalErr
	}

	fs := osfs.New(dotGit)
	s := &extensionStrippingStorer{Storer: gogitfs.NewStorage(fs, cache.NewObjectLRUDefault())}
	wt := osfs.New(worktreePath)
	repo, openErr := git.Open(s, wt)
	if openErr != nil {
		return nil, originalErr
	}
	return repo, nil
}

// resolveDotGit returns the .git directory path and the worktree root for path.
func resolveDotGit(path string) (dotGit, worktree string, err error) {
	candidate := filepath.Join(path, ".git")
	fi, statErr := os.Stat(candidate)
	if statErr == nil && fi.IsDir() {
		return candidate, path, nil
	}

	// Could be a bare repository (git dir is path itself).
	headPath := filepath.Join(path, "HEAD")
	if _, headErr := os.Stat(headPath); headErr == nil {
		return path, path, nil
	}

	// Could be a linked worktree: .git is a file containing "gitdir: <path>".
	if statErr == nil && !fi.IsDir() {
		target, readErr := resolveGitFile(candidate)
		if readErr != nil {
			return "", "", readErr
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(path, target)
		}
		return target, path, nil
	}

	return "", "", errors.New("git: cannot locate .git directory")
}

// resolveGitFile reads a .git file and extracts the "gitdir: <path>" value.
func resolveGitFile(gitFile string) (string, error) {
	data, err := os.ReadFile(gitFile)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(data))
	const prefix = "gitdir:"
	if !strings.HasPrefix(line, prefix) {
		return "", errors.New("git: malformed .git file: missing 'gitdir:' prefix")
	}
	return strings.TrimSpace(line[len(prefix):]), nil
}

// extensionStrippingStorer wraps a storage.Storer and removes Git extensions
// that go-git falsely rejects due to key-casing bugs in its allowlist check.
// Only extensions that go-git does not implement anyway are stripped; unknown
// extensions that would indicate genuinely incompatible repository formats are
// left in place so that verifyExtensions can still reject them.
type extensionStrippingStorer struct {
	storage.Storer
}

// safeToStrip lists extension names (lowercase) that go-git may falsely reject
// but does not implement; stripping them from the config view is safe.
var safeToStrip = map[string]bool{
	"worktreeconfig": true,
}

func (s *extensionStrippingStorer) Config() (*gogitconfig.Config, error) {
	cfg, err := s.Storer.Config()
	if err != nil || cfg == nil || cfg.Raw == nil {
		return cfg, err
	}
	if !cfg.Raw.HasSection("extensions") {
		return cfg, nil
	}
	section := cfg.Raw.Section("extensions")
	kept := section.Options[:0]
	for _, opt := range section.Options {
		if !safeToStrip[strings.ToLower(opt.Key)] {
			kept = append(kept, opt)
		}
	}
	section.Options = kept
	return cfg, nil
}
