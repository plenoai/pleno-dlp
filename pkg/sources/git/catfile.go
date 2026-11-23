package git

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// catFileBatch is one long-lived `git cat-file --batch` process shared by
// a parser for blob lookups. Spawning a `git cat-file blob` process per
// binary patch dominated wall time on histories with many binary files
// (django: ~32k binary patches, ~10ms of fork/exec each), so lookups are
// multiplexed over a single pipe instead. Not safe for concurrent use.
type catFileBatch struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr limitedWriter
	broken error
}

func startCatFileBatch(ctx context.Context, gitBin, repoAbs string) (*catFileBatch, error) {
	return startCatFileBatchArgs(ctx, gitBin, repoAbs, "--batch")
}

func startCatFileBatchArgs(ctx context.Context, gitBin, repoAbs string, mode ...string) (*catFileBatch, error) {
	b := &catFileBatch{}
	b.stderr.limit = nativeStderrLimit
	b.cmd = exec.CommandContext(ctx, gitBin, append([]string{"-C", repoAbs, "cat-file"}, mode...)...)
	b.cmd.Env = nativeGitEnv()
	b.cmd.Stderr = &b.stderr
	stdin, err := b.cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("git: cat-file batch stdin: %w", err)
	}
	stdout, err := b.cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("git: cat-file batch stdout: %w", err)
	}
	if err := b.cmd.Start(); err != nil {
		return nil, fmt.Errorf("git: start cat-file batch: %w", err)
	}
	b.stdin = stdin
	b.stdout = bufio.NewReaderSize(stdout, 64<<10)
	return b, nil
}

// errCatFileMissing reports an object the batch process could not resolve.
var errCatFileMissing = errors.New("object missing")

// blobContainsNUL streams the blob named by object ("<rev>:<path>") and
// reports whether it contains a NUL byte. The whole blob is consumed so the
// pipe stays framed for the next request.
func (b *catFileBatch) blobContainsNUL(ctx context.Context, object string) (bool, error) {
	if b.broken != nil {
		return false, b.broken
	}
	if strings.ContainsAny(object, "\n") {
		return false, fmt.Errorf("git: cat-file batch cannot address %q", object)
	}
	if _, err := io.WriteString(b.stdin, object+"\n"); err != nil {
		return false, b.fail(fmt.Errorf("git: cat-file batch write: %w", err))
	}
	header, err := b.stdout.ReadString('\n')
	if err != nil {
		return false, b.fail(fmt.Errorf("git: cat-file batch header: %w", err))
	}
	header = strings.TrimSuffix(header, "\n")
	fields := strings.Fields(header)
	if len(fields) == 2 && (fields[1] == "missing" || fields[1] == "ambiguous") {
		return false, fmt.Errorf("git: %s: %w", object, errCatFileMissing)
	}
	if len(fields) != 3 {
		return false, b.fail(fmt.Errorf("git: cat-file batch malformed header %q", header))
	}
	size, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || size < 0 {
		return false, b.fail(fmt.Errorf("git: cat-file batch malformed size in %q", header))
	}
	binary := false
	remaining := size
	for remaining > 0 {
		if err := ctx.Err(); err != nil {
			return false, b.fail(err)
		}
		n := int64(b.stdout.Buffered())
		if n == 0 {
			if _, err := b.stdout.Peek(1); err != nil {
				return false, b.fail(fmt.Errorf("git: cat-file batch body: %w", err))
			}
			n = int64(b.stdout.Buffered())
		}
		if n > remaining {
			n = remaining
		}
		chunk, _ := b.stdout.Peek(int(n))
		if !binary && bytes.IndexByte(chunk, 0x00) >= 0 {
			binary = true
		}
		if _, err := b.stdout.Discard(int(n)); err != nil {
			return false, b.fail(fmt.Errorf("git: cat-file batch body: %w", err))
		}
		remaining -= n
	}
	if c, err := b.stdout.ReadByte(); err != nil || c != '\n' {
		return false, b.fail(fmt.Errorf("git: cat-file batch missing record terminator"))
	}
	if fields[1] != "blob" {
		return false, fmt.Errorf("git: %s is a %s, not a blob", object, fields[1])
	}
	return binary, nil
}

func (b *catFileBatch) fail(err error) error {
	if detail := strings.TrimSpace(b.stderr.String()); detail != "" {
		err = fmt.Errorf("%w: %s", err, detail)
	}
	b.broken = err
	return err
}

func (b *catFileBatch) close() error {
	if b == nil || b.cmd == nil {
		return nil
	}
	_ = b.stdin.Close()
	if b.broken != nil && b.cmd.Process != nil {
		_ = b.cmd.Process.Kill()
	}
	err := b.cmd.Wait()
	b.cmd = nil
	if b.broken != nil {
		return nil
	}
	return err
}

// parseNativeIndexNewOID extracts the post-image blob id from a patch
// "index <old>..<new>[ <mode>]" header, returning "" unless it is a full
// 40-hex id (nativeLogArgs passes --abbrev=40).
func parseNativeIndexNewOID(line []byte) string {
	rest := strings.TrimSpace(string(line[len("index "):]))
	_, after, ok := strings.Cut(rest, "..")
	if !ok {
		return ""
	}
	if sp := strings.IndexByte(after, ' '); sp >= 0 {
		after = after[:sp]
	}
	if len(after) != 40 || strings.Trim(after, "0123456789abcdef") != "" || after == strings.Repeat("0", 40) {
		return ""
	}
	return after
}

// binaryBlobCacheLimit bounds the per-walk classification cache.
const binaryBlobCacheLimit = 1 << 20

// binaryBlobCache memoizes NUL classification by blob id across the
// parallel shards of one walk.
type binaryBlobCache struct {
	mu sync.Mutex
	m  map[string]bool
}

func (c *binaryBlobCache) lookup(oid string) (bool, bool) {
	if c == nil {
		return false, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[oid]
	return v, ok
}

func (c *binaryBlobCache) store(oid string, binary bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[string]bool)
	}
	if len(c.m) < binaryBlobCacheLimit {
		c.m[oid] = binary
	}
}
