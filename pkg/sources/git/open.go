// Repository opening with worktree layouts and benign extensions tolerated.
//
// go-git's PlainOpen rejects every repository whose config declares an
// [extensions] entry outside its tiny builtin set — including
// extensions.worktreeConfig, which real checkouts (and this repository's own
// worktrees) set routinely, and extensions.partialClone/preciousObjects that
// git may write for format-version 0 repositories. The rejection happens
// inside go-git.Open's verifyExtensions before any object access.
//
// The scanner only reads objects and refs, so the three extensions above are
// safe to ignore: worktreeConfig merely relocates worktree settings into
// config.worktree (irrelevant to history walks), partialClone is the promisor
// marker the partial-clone walk already handles, and preciousObjects is a GC
// hint. OpenRepository therefore serves go-git a filtered *view* of the
// config — those option lines removed in memory only — while leaving the
// file on disk byte-identical and letting unknown extensions (objectFormat,
// refStorage, …) keep failing exactly as upstream intends.
//
// The open also resolves linked-worktree layouts: a `.git` *file* pointing at
// the per-worktree gitdir, and that gitdir's `commondir` file pointing back
// at the shared object/ref store — both features go-git supports but only
// behind PlainOpenWithOptions.EnableDotGitCommonDir, which PlainOpen leaves
// off.
package git

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	gitfilesystem "github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/go-git/go-git/v5/storage/filesystem/dotgit"
	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
)

// ignorableConfigExtensions are [extensions] option keys (lowercased) a
// read-only history scan can drop without changing results. Anything not in
// this set must keep flowing into go-git's verifier so unsupported on-disk
// formats still fail closed.
var ignorableConfigExtensions = map[string]struct{}{
	"worktreeconfig":  {},
	"partialclone":    {},
	"preciousobjects": {},
	"noop":            {},
	"noop-v1":         {},
}

// OpenRepository opens path like gogit.PlainOpen but additionally resolves
// linked worktrees (gitfile + commondir) and tolerates the benign repository
// extensions listed above. The repository config on disk is never modified.
func OpenRepository(path string) (*gogit.Repository, error) {
	dot, wt, err := repositoryFilesystems(path)
	if err != nil {
		return nil, err
	}
	if _, err := dot.Stat(""); err != nil {
		if os.IsNotExist(err) {
			return nil, gogit.ErrRepositoryNotExists
		}
		return nil, err
	}
	common, err := dotGitCommonDirectory(dot)
	if err != nil {
		return nil, err
	}
	repositoryFs := billy.Filesystem(dotgit.NewRepositoryFilesystem(dot, common))
	s := gitfilesystem.NewStorage(extensionFilterFS{repositoryFs}, cache.NewObjectLRUDefault())
	return gogit.Open(s, wt)
}

// repositoryFilesystems mirrors go-git's dotGitToOSFilesystems(path, false):
// <path>/.git as a directory means a normal checkout, as a file means a
// linked worktree whose `gitdir:` target must be resolved, and absent means
// path itself is the (bare) gitdir.
func repositoryFilesystems(path string) (dot, wt billy.Filesystem, err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}
	fs := osfs.New(path)
	fi, err := fs.Stat(".git")
	switch {
	case err == nil && fi.IsDir():
		dot, err = fs.Chroot(".git")
		return dot, fs, err
	case err == nil:
		dot, err = gitFileToOSFilesystem(path, fs)
		if err != nil {
			return nil, nil, err
		}
		return dot, fs, nil
	case os.IsNotExist(err):
		return fs, nil, nil
	default:
		return nil, nil, err
	}
}

// gitFileToOSFilesystem resolves a `.git` file's `gitdir: <path>` target.
func gitFileToOSFilesystem(path string, fs billy.Filesystem) (billy.Filesystem, error) {
	f, err := fs.Open(".git")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	line := string(b)
	const prefix = "gitdir: "
	if !strings.HasPrefix(line, prefix) {
		return nil, fmt.Errorf("git: .git file has no %q prefix", prefix)
	}
	gitdir := strings.TrimSpace(strings.SplitN(line[len(prefix):], "\n", 2)[0])
	if filepath.IsAbs(gitdir) {
		return osfs.New(gitdir), nil
	}
	return osfs.New(filepath.Join(path, gitdir)), nil
}

// dotGitCommonDirectory resolves a gitdir's `commondir` file — present in
// linked worktrees — to the shared repository directory holding objects,
// refs, and the main config. Mirrors go-git's dotGitCommonDirectory.
func dotGitCommonDirectory(fs billy.Filesystem) (billy.Filesystem, error) {
	f, err := fs.Open("commondir")
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	path := strings.TrimSpace(string(b))
	var common billy.Filesystem
	if filepath.IsAbs(path) {
		common = osfs.New(path)
	} else {
		common = osfs.New(filepath.Join(fs.Root(), path))
	}
	if _, err := common.Stat(""); err != nil {
		if os.IsNotExist(err) {
			return nil, gogit.ErrRepositoryIncomplete
		}
		return nil, err
	}
	return common, nil
}

// extensionFilterFS serves the repository config with ignorable [extensions]
// options removed. Every other file — and every other config option — is
// passed through untouched.
type extensionFilterFS struct {
	billy.Filesystem
}

func (fs extensionFilterFS) Open(filename string) (billy.File, error) {
	return fs.openConfig(filename, func(name string) (billy.File, error) {
		return fs.Filesystem.Open(name)
	})
}

func (fs extensionFilterFS) OpenFile(filename string, flag int, perm os.FileMode) (billy.File, error) {
	if flag != os.O_RDONLY {
		return fs.Filesystem.OpenFile(filename, flag, perm)
	}
	return fs.openConfig(filename, func(name string) (billy.File, error) {
		return fs.Filesystem.OpenFile(name, flag, perm)
	})
}

func (fs extensionFilterFS) Chroot(path string) (billy.Filesystem, error) {
	chrooted, err := fs.Filesystem.Chroot(path)
	if err != nil {
		return nil, err
	}
	return extensionFilterFS{chrooted}, nil
}

func (fs extensionFilterFS) openConfig(filename string, open func(string) (billy.File, error)) (billy.File, error) {
	f, err := open(filename)
	if err != nil || filepath.ToSlash(filename) != "config" {
		return f, err
	}
	data, err := io.ReadAll(f)
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	return &filteredConfigFile{Reader: bytes.NewReader(filterConfigExtensions(data)), name: filename}, nil
}

// filterConfigExtensions removes ignorable option lines from the
// [extensions] section of a git config file. Lines, sections, and ordering
// are otherwise preserved byte-for-byte; an emptied section header stays.
func filterConfigExtensions(data []byte) []byte {
	lines := bytes.Split(data, []byte("\n"))
	out := make([][]byte, 0, len(lines))
	inExtensions := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(string(line))
		if strings.HasPrefix(trimmed, "[") {
			inExtensions = configSectionName(trimmed) == "extensions"
			out = append(out, line)
			continue
		}
		if inExtensions {
			key := configOptionKey(trimmed)
			if _, drop := ignorableConfigExtensions[key]; drop && key != "" {
				continue
			}
		}
		out = append(out, line)
	}
	return bytes.Join(out, []byte("\n"))
}

// configSectionName extracts the section name from a `[name]` or
// `[name "sub"]` header line.
func configSectionName(header string) string {
	end := strings.IndexByte(header, ']')
	if end < 0 {
		end = len(header)
	}
	name := strings.TrimSpace(header[1:end])
	if i := strings.IndexByte(name, ' '); i >= 0 {
		name = name[:i]
	}
	return strings.ToLower(name)
}

// configOptionKey extracts the lowercased option key from a `key = value` or
// bare `key` line. Comment lines return "".
func configOptionKey(line string) string {
	if line == "" || line[0] == '#' || line[0] == ';' {
		return ""
	}
	if i := strings.IndexByte(line, '='); i >= 0 {
		line = line[:i]
	}
	return strings.ToLower(strings.TrimSpace(line))
}

// filteredConfigFile is a read-only in-memory billy.File over filtered
// config bytes. Writes and truncation fail; locks are no-ops.
type filteredConfigFile struct {
	*bytes.Reader
	name string
}

func (f *filteredConfigFile) Name() string                  { return f.name }
func (f *filteredConfigFile) Write([]byte) (int, error)     { return 0, errors.New("git: filtered config is read-only") }
func (f *filteredConfigFile) Lock() error                   { return nil }
func (f *filteredConfigFile) Unlock() error                 { return nil }
func (f *filteredConfigFile) Truncate(int64) error          { return errors.New("git: filtered config is read-only") }
func (f *filteredConfigFile) Close() error                  { return nil }
