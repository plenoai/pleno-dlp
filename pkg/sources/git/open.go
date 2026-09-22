package git

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/cache"
	formatcfg "github.com/go-git/go-git/v5/plumbing/format/config"
	gitfilesystem "github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/go-git/go-git/v5/storage/filesystem/dotgit"
)

// worktreeConfigStorage presents the repository config to go-git with the
// extensions.worktreeConfig option removed. go-git v5.19.x lowercases
// extension names before checking them against a camelCase repositoryformat
// allowlist, so every repository carrying extensions.worktreeConfig (plain
// or linked worktree) is rejected before open. Stripping this one option at
// read time keeps go-git's extension check strict for every other unknown
// extension and does not alter the on-disk config; config.worktree contents
// are not loaded by either implementation.
type worktreeConfigStorage struct {
	*gitfilesystem.Storage
}

func (s worktreeConfigStorage) Config() (*gitconfig.Config, error) {
	cfg, err := s.Storage.Config()
	if err != nil || cfg == nil || cfg.Raw == nil || !cfg.Raw.HasSection("extensions") {
		return cfg, err
	}
	section := cfg.Raw.Section("extensions")
	kept := make(formatcfg.Options, 0, len(section.Options))
	for _, opt := range section.Options {
		if opt.IsKey("worktreeConfig") {
			continue
		}
		kept = append(kept, opt)
	}
	section.Options = kept
	return cfg, nil
}

// openRepository opens a repository like go-git's PlainOpen but with
// commondir resolution enabled and tolerance for the worktreeConfig
// extension. Every other unknown extension is still rejected by go-git's
// own extension verification.
func openRepository(path string) (*git.Repository, error) {
	dot, wt, err := dotGitFilesystems(path)
	if err != nil {
		return nil, err
	}
	if _, err := dot.Stat(""); err != nil {
		if os.IsNotExist(err) {
			return nil, git.ErrRepositoryNotExists
		}
		return nil, err
	}
	repositoryFS := dot
	if commonDir, err := dotGitCommonFilesystem(dot); err != nil {
		return nil, err
	} else if commonDir != nil {
		repositoryFS = dotgit.NewRepositoryFilesystem(dot, commonDir)
	}
	storage := gitfilesystem.NewStorage(repositoryFS, cache.NewObjectLRUDefault())
	return git.Open(worktreeConfigStorage{storage}, wt)
}

// dotGitFilesystems mirrors go-git's unexported dotGitToOSFilesystems for a
// direct repository path (no parent detection): .git may be a directory or a
// "gitdir: <path>" file as created by `git worktree` and `git clone
// --separate-git-dir`.
func dotGitFilesystems(path string) (dot, wt billy.Filesystem, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}
	fs := osfs.New(abs)
	fi, err := fs.Stat(git.GitDirName)
	if err != nil {
		if os.IsNotExist(err) {
			return fs, nil, nil
		}
		return nil, nil, err
	}
	if fi.IsDir() {
		dot, err := fs.Chroot(git.GitDirName)
		return dot, fs, err
	}
	f, err := fs.Open(git.GitDirName)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	line := string(body)
	const prefix = "gitdir: "
	if !strings.HasPrefix(line, prefix) {
		return nil, nil, fmt.Errorf(".git file has no %s prefix", prefix)
	}
	gitdir := strings.TrimSpace(strings.SplitN(line[len(prefix):], "\n", 2)[0])
	if filepath.IsAbs(gitdir) {
		return osfs.New(gitdir), fs, nil
	}
	return osfs.New(fs.Join(abs, gitdir)), fs, nil
}

// dotGitCommonFilesystem resolves the .git/commondir file present in linked
// worktrees, mirroring go-git's unexported dotGitCommonDirectory.
func dotGitCommonFilesystem(fs billy.Filesystem) (billy.Filesystem, error) {
	f, err := fs.Open("commondir")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	body, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, nil
	}
	path := strings.TrimSpace(string(body))
	var commonDir billy.Filesystem
	if filepath.IsAbs(path) {
		commonDir = osfs.New(path)
	} else {
		commonDir = osfs.New(filepath.Join(fs.Root(), path))
	}
	if _, err := commonDir.Stat(""); err != nil {
		if os.IsNotExist(err) {
			return nil, git.ErrRepositoryIncomplete
		}
		return nil, err
	}
	return commonDir, nil
}
