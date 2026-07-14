package fixture

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/engine"
)

type Spec struct {
	Commits int `json:"commits"`
	Files   int `json:"files"`
}

type Inventory struct {
	Blobs     int   `json:"blobs"`
	Commits   int   `json:"commits"`
	Trees     int   `json:"trees"`
	Total     int   `json:"total"`
	PackBytes int64 `json:"pack_bytes"`
}

type Metadata struct {
	Repo          string    `json:"-"`
	Head          string    `json:"head"`
	Canary        string    `json:"-"`
	CanaryCommit  string    `json:"canary_commit"`
	CanaryPath    string    `json:"canary_path"`
	CanaryOrdinal int       `json:"canary_ordinal"`
	Inventory     Inventory `json:"inventory"`
}

type Snapshot struct {
	Head         string    `json:"head"`
	CanaryCommit string    `json:"canary_commit"`
	Inventory    Inventory `json:"inventory"`
}

func Generate(ctx context.Context, repo string, spec Spec) (Metadata, error) {
	if spec.Commits < 1 || spec.Files < 1 {
		return Metadata{}, errors.New("commits and files must be positive")
	}
	abs, err := filepath.Abs(repo)
	if err != nil {
		return Metadata{}, err
	}
	if _, err := os.Stat(abs); !os.IsNotExist(err) {
		if err == nil {
			return Metadata{}, fmt.Errorf("fixture path already exists: %s", abs)
		}
		return Metadata{}, err
	}
	if _, err := runGit(ctx, "init", "--bare", "--quiet", "--object-format=sha1", abs); err != nil {
		return Metadata{}, err
	}

	canary := canaryToken()
	if engine.IsPlaceholder([]byte(canary)) {
		return Metadata{}, errors.New("generated canary is classified as a placeholder")
	}
	canaryIndex := spec.Commits / 2
	canaryPath := fixturePath(canaryIndex % spec.Files)

	cmd := exec.CommandContext(ctx, "git", "-C", abs, "fast-import", "--quiet")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return Metadata{}, err
	}
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return Metadata{}, err
	}

	w := &importWriter{w: bufio.NewWriterSize(stdin, 1<<20)}
	previousCommitMark := 0
	for i := 0; i < spec.Commits; i++ {
		blobMark := 2*i + 1
		commitMark := 2*i + 2
		content := fmt.Sprintf("value-%08d\n", i)
		if i == canaryIndex {
			content = "token=" + canary + "\n"
		}
		message := fmt.Sprintf("commit-%08d", i)
		w.printf("blob\nmark :%d\ndata %d\n%s", blobMark, len(content), content)
		w.printf("commit refs/heads/main\nmark :%d\n", commitMark)
		w.printf("author Probe <probe@example.invalid> %d +0000\n", 1700000000+i)
		w.printf("committer Probe <probe@example.invalid> %d +0000\n", 1700000000+i)
		w.printf("data %d\n%s\n", len(message), message)
		if previousCommitMark != 0 {
			w.printf("from :%d\n", previousCommitMark)
		}
		w.printf("M 100644 :%d %s\n\n", blobMark, fixturePath(i%spec.Files))
		if i == canaryIndex {
			w.printf("reset refs/bench/canary\nfrom :%d\n\n", commitMark)
		}
		previousCommitMark = commitMark
	}
	if err := w.close(stdin); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return Metadata{}, err
	}
	if err := cmd.Wait(); err != nil {
		return Metadata{}, fmt.Errorf("git fast-import: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if _, err := runGit(ctx, "-C", abs, "symbolic-ref", "HEAD", "refs/heads/main"); err != nil {
		return Metadata{}, err
	}
	if _, err := runGit(ctx, "-C", abs, "repack", "-adq"); err != nil {
		return Metadata{}, err
	}

	snapshot, err := Inspect(ctx, abs)
	if err != nil {
		return Metadata{}, err
	}
	return Metadata{
		Repo:          abs,
		Head:          snapshot.Head,
		Canary:        canary,
		CanaryCommit:  snapshot.CanaryCommit,
		CanaryPath:    canaryPath,
		CanaryOrdinal: canaryIndex + 1,
		Inventory:     snapshot.Inventory,
	}, nil
}

func Inspect(ctx context.Context, repo string) (Snapshot, error) {
	head, err := runGit(ctx, "-C", repo, "rev-parse", "refs/heads/main")
	if err != nil {
		return Snapshot{}, err
	}
	canaryCommit, err := runGit(ctx, "-C", repo, "rev-parse", "refs/bench/canary")
	if err != nil {
		return Snapshot{}, err
	}
	inv, err := CountObjects(ctx, repo)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Head:         strings.TrimSpace(string(head)),
		CanaryCommit: strings.TrimSpace(string(canaryCommit)),
		Inventory:    inv,
	}, nil
}

func CountObjects(ctx context.Context, repo string) (Inventory, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "cat-file", "--batch-check=%(objecttype)", "--batch-all-objects")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Inventory{}, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return Inventory{}, err
	}
	var inv Inventory
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		switch scanner.Text() {
		case "blob":
			inv.Blobs++
		case "commit":
			inv.Commits++
		case "tree":
			inv.Trees++
		default:
			return Inventory{}, fmt.Errorf("unexpected object type %q", scanner.Text())
		}
	}
	if err := scanner.Err(); err != nil {
		return Inventory{}, err
	}
	if err := cmd.Wait(); err != nil {
		return Inventory{}, fmt.Errorf("git cat-file: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	inv.Total = inv.Blobs + inv.Commits + inv.Trees
	entries, err := os.ReadDir(filepath.Join(repo, "objects", "pack"))
	if err != nil {
		return Inventory{}, err
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pack" {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return Inventory{}, err
		}
		inv.PackBytes += info.Size()
	}
	return inv, nil
}

func ExpectedInventory(spec Spec) Inventory {
	return Inventory{Blobs: spec.Commits, Commits: spec.Commits, Trees: 3 * spec.Commits, Total: 5 * spec.Commits}
}

func CanaryToken() string { return canaryToken() }

func canaryToken() string {
	sum := sha256.Sum256([]byte("pleno-dlp git history benchmark canary v1"))
	prefix := strings.Join([]string{"g", "hp", "_"}, "")
	return prefix + hex.EncodeToString(sum[:])[:36]
}

func fixturePath(index int) string {
	return fmt.Sprintf("d%04x/s%02x/f%08x.txt", index/256, index%256, index)
}

type importWriter struct {
	w   *bufio.Writer
	err error
}

func (w *importWriter) printf(format string, args ...any) {
	if w.err != nil {
		return
	}
	_, w.err = fmt.Fprintf(w.w, format, args...)
}

func (w *importWriter) close(dst io.Closer) error {
	if w.err == nil {
		w.err = w.w.Flush()
	}
	if err := dst.Close(); w.err == nil {
		w.err = err
	}
	return w.err
}

func runGit(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
