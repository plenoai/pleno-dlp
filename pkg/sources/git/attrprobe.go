package git

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/format/index"
)

// Attribute-source probe (#1042).
//
// Every in-process renderer used to fork `git check-attr --stdin` and ask
// it for the "diff" attribute of each new path; on small histories the
// lookups cost more CPU than the diffs. When the walk can prove that git
// has no attribute source at all, every path is "unspecified" and the
// helper is skipped. The proof is deliberately conservative: anything it
// cannot rule out — a bare repository (attributes come from HEAD), any
// .gitattributes in the worktree or index, $GIT_DIR/info/attributes, the
// global or system file, core.attributesFile, attr.tree, GIT_ATTR_SOURCE,
// a sparse index, or a probe failure — keeps check-attr.

// noDiffAttributes reports, once per walk, whether git provably resolves
// no attributes for any path of this repository.
func (s *Source) noDiffAttributes(ctx context.Context, gitBin string) bool {
	c := s.diffAttrs
	if c == nil {
		return false
	}
	c.probeOnce.Do(func() {
		if os.Getenv("PLENO_DLP_GIT_ATTR_PROBE") == "0" {
			return
		}
		c.none = probeNoAttributeSources(ctx, gitBin, s.repoAbs)
	})
	return c.none
}

func probeNoAttributeSources(ctx context.Context, gitBin, repoAbs string) bool {
	if _, set := os.LookupEnv("GIT_ATTR_SOURCE"); set {
		return false
	}
	cmd := exec.CommandContext(ctx, gitBin, "-C", repoAbs, "rev-parse", "--path-format=absolute", "--is-bare-repository", "--git-common-dir", "--git-dir", "--show-toplevel")
	cmd.Env = nativeGitEnv()
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != 4 || lines[0] != "false" {
		return false
	}
	common, gitDir, top := lines[1], lines[2], lines[3]
	if top == "" || fileMayExist(filepath.Join(common, "info", "attributes")) {
		return false
	}
	cmd = exec.CommandContext(ctx, gitBin, "-C", repoAbs, "var", "-l")
	cmd.Env = nativeGitEnv()
	out, err = cmd.Output()
	if err != nil {
		return false
	}
	sawGlobal := false
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		key, value, _ := strings.Cut(sc.Text(), "=")
		switch strings.ToLower(key) {
		case "core.attributesfile", "attr.tree":
			return false
		}
		switch key {
		case "GIT_ATTR_SYSTEM":
			if value != "" && fileMayExist(value) {
				return false
			}
		case "GIT_ATTR_GLOBAL":
			sawGlobal = true
			if value != "" && fileMayExist(value) {
				return false
			}
		}
	}
	if sc.Err() != nil || !sawGlobal {
		// Older git (before 2.42) cannot name its attribute files. git
		// omits GIT_ATTR_SYSTEM when the system files are disabled.
		return false
	}
	if indexHasAttributes(gitDir) {
		return false
	}
	return !worktreeHasAttributes(ctx, top)
}

// fileMayExist is true unless path provably does not exist.
func fileMayExist(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// indexHasAttributes reports whether the index names a .gitattributes file
// (or cannot be read, or is sparse).
func indexHasAttributes(gitDir string) bool {
	f, err := os.Open(filepath.Join(gitDir, "index"))
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	defer f.Close()
	var idx index.Index
	if err := index.NewDecoder(bufio.NewReader(f)).Decode(&idx); err != nil {
		return true
	}
	for _, e := range idx.Entries {
		if e.Mode == filemode.Dir || e.Name == ".gitattributes" || strings.HasSuffix(e.Name, "/.gitattributes") {
			return true
		}
	}
	return false
}

// worktreeHasAttributes reports whether any .gitattributes exists below
// top, including in untracked, ignored, and nested-repository directories
// (check-attr reads them from disk by path).
func worktreeHasAttributes(ctx context.Context, top string) bool {
	found := false
	err := filepath.WalkDir(top, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.Name() == ".gitattributes" {
			found = true
			return filepath.SkipAll
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// A symlinked directory may lead check-attr to attribute files
			// outside the walk.
			if st, serr := os.Stat(path); serr != nil || st.IsDir() {
				found = true
				return filepath.SkipAll
			}
			return nil
		}
		if d.IsDir() && d.Name() == ".git" && path != top {
			return filepath.SkipDir
		}
		return nil
	})
	return found || err != nil
}
