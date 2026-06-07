package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// pii-server materializes the pleno-anonymize HTTP server via uv.
// It uses a cached clone plus `uv sync` / `uv run` so the upstream
// workspace layout resolves correctly.

type piiServerFlags struct {
	port     int
	host     string
	gitRef   string
	source   string
	cacheDir string
	noFetch  bool
}

var piiServerOpts piiServerFlags

// Tests can override uvBin and gitBin with fake executables.
var (
	uvBin  = "uv"
	gitBin = "git"
)

// defaultPIIServerSource is the canonical clone URL.
const defaultPIIServerSource = "git+https://github.com/plenoai/pleno-anonymize.git"

// nerWheelURLs are installed after sync because they live outside PyPI.
var nerWheelURLs = []string{
	"https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl",
	"https://huggingface.co/0xhikae/ja-ner-ja/resolve/main/ja_ner_ja-0.2.0-py3-none-any.whl",
	"https://huggingface.co/0xhikae/en-ner-en/resolve/main/en_ner_en-0.1.0.tar.gz",
}

var piiServerCmd = &cobra.Command{
	Use:   "pii-server",
	Short: "Run the pleno-anonymize HTTP server (used by --pii-engine=anonymize)",
	Long: "pii-server foreground-spawns the pleno-anonymize HTTP server via uv.\n" +
		"\n" +
		"Required runtime: uv (https://docs.astral.sh/uv/) and Python 3.12+.\n" +
		"git is required when --source is a git+ URL (the default).\n" +
		"No Docker required.\n" +
		"\n" +
		"Strategy: clone the upstream repo into a cache directory, run\n" +
		"`uv sync --package pleno-anonymize-server` to resolve the workspace,\n" +
		"install the NER model wheels (which sync would otherwise prune), then\n" +
		"`uv run --no-sync uvicorn server.src.app:app`. The cache directory\n" +
		"defaults to <user-cache>/pleno-dlp/pleno-anonymize and is reused\n" +
		"across invocations — only a `git fetch` runs on subsequent calls\n" +
		"unless --no-fetch is set.\n" +
		"\n" +
		"Typical usage is indirect — 'pleno-dlp scan --pii-engine=anonymize'\n" +
		"invokes this subcommand on an ephemeral loopback port and tears it\n" +
		"down at scan end. Direct invocation is supported for ad-hoc local use:\n" +
		"\n" +
		"  pleno-dlp pii-server --port 8080\n" +
		"  pleno-dlp pii-server                  # ephemeral; resolved port is printed\n" +
		"  pleno-dlp pii-server --git-ref v0.5.0 # pin to a tag\n" +
		"  pleno-dlp pii-server --no-fetch       # use the cached checkout as-is\n" +
		"  pleno-dlp pii-server --source /path/to/checkout  # local workspace root\n" +
		"\n" +
		"--host is restricted to loopback / RFC1918 / link-local addresses; binding\n" +
		"a public interface is refused so a DLP tool cannot accidentally relay scanned\n" +
		"text to a non-trusted listener.",
	Args: cobra.NoArgs,
	RunE: runPIIServer,
}

func init() {
	piiServerCmd.Flags().IntVar(&piiServerOpts.port, "port", 0,
		"port to bind (0 = auto-allocate an ephemeral loopback port; the resolved port is printed to stdout)")
	piiServerCmd.Flags().StringVar(&piiServerOpts.host, "host", "127.0.0.1",
		"bind address (loopback / RFC1918 / link-local only; refuses 0.0.0.0 and any public address)")
	piiServerCmd.Flags().StringVar(&piiServerOpts.gitRef, "git-ref", "",
		"git ref (tag/branch/sha) of pleno-anonymize to check out; empty = main (clone) / leave checkout alone (fetch)")
	piiServerCmd.Flags().StringVar(&piiServerOpts.source, "source", defaultPIIServerSource,
		"clone source. A `git+<URL>` value triggers cached clone+fetch; an absolute filesystem path is treated as an existing workspace root and used in-place.")
	piiServerCmd.Flags().StringVar(&piiServerOpts.cacheDir, "cache-dir", "",
		"directory holding the cached pleno-anonymize checkout and uv venv. Empty = $PLENO_DLP_ANONYMIZE_CACHE if set, else <os.UserCacheDir>/pleno-dlp/pleno-anonymize. Created with 0o700 perms.")
	piiServerCmd.Flags().BoolVar(&piiServerOpts.noFetch, "no-fetch", false,
		"skip the `git fetch` on warm cache; use the existing checkout as-is. Useful for offline use and reproducible runs.")
	Root.AddCommand(piiServerCmd)
}

func runPIIServer(cmd *cobra.Command, _ []string) error {
	if err := validatePIIServerHost(piiServerOpts.host); err != nil {
		return err
	}
	if _, err := exec.LookPath(uvBin); err != nil {
		return fmt.Errorf("uv not found on PATH (install uv: https://docs.astral.sh/uv/): %w", err)
	}

	port := piiServerOpts.port
	if port == 0 {
		p, err := pickEphemeralPort(piiServerOpts.host)
		if err != nil {
			return fmt.Errorf("allocate ephemeral port: %w", err)
		}
		port = p
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stderr := cmd.ErrOrStderr()

	workdir, freshCheckout, err := prepareWorkdir(ctx, prepareInput{
		source:   piiServerOpts.source,
		gitRef:   piiServerOpts.gitRef,
		cacheDir: piiServerOpts.cacheDir,
		noFetch:  piiServerOpts.noFetch,
		stderr:   stderr,
	})
	if err != nil {
		return err
	}

	if err := runUVSync(ctx, workdir, stderr); err != nil {
		return fmt.Errorf("uv sync: %w", err)
	}
	if freshCheckout {
		if err := runUVPipInstallNERWheels(ctx, workdir, stderr); err != nil {
			return fmt.Errorf("install NER wheels: %w", err)
		}
	}

	argv := buildPIIServerArgv(uvBin, piiServerOpts.host, port)

	fmt.Fprintf(cmd.OutOrStdout(), "pii-server: listening on %s:%d\n", piiServerOpts.host, port)

	child := exec.CommandContext(ctx, argv[0], argv[1:]...)
	child.Dir = workdir
	child.Stdin = cmd.InOrStdin()
	child.Stdout = cmd.OutOrStdout()
	child.Stderr = cmd.ErrOrStderr()
	child.Cancel = func() error {
		if child.Process == nil {
			return nil
		}
		return child.Process.Signal(syscall.SIGTERM)
	}
	child.WaitDelay = 5 * time.Second

	if err := child.Run(); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("uv run: %w", err)
	}
	return nil
}

// validatePIIServerHost rejects unspecified and public bind addresses.
func validatePIIServerHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("--host: empty")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("--host %q: must be a literal IP or 'localhost' (DNS resolution is intentionally not performed)", host)
	}
	if ip.IsUnspecified() {
		return fmt.Errorf("--host %q: refusing to bind a public/unspecified interface for a DLP tool", host)
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return nil
	}
	return fmt.Errorf("--host %q: only loopback, RFC1918, or link-local addresses are accepted", host)
}

// pickEphemeralPort reserves a free port on host by listening on
// `host:0` and immediately closing. There is a TOCTOU window before
// uvicorn's own bind, but for this CLI's audience (single-developer or
// CI runner, low contention) it's the standard pattern; uvicorn's
// own bind failure surfaces as a non-zero exit if the race lost.
func pickEphemeralPort(host string) (int, error) {
	l, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	defer l.Close()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return 0, fmt.Errorf("unexpected listen address type %T", l.Addr())
	}
	return addr.Port, nil
}

// prepareInput collects what prepareWorkdir needs without taking a
// dependency on the global piiServerOpts; this keeps prepareWorkdir
// drivable from tests with a tempdir-rooted PLENO_DLP_ANONYMIZE_CACHE.
type prepareInput struct {
	source   string
	gitRef   string
	cacheDir string
	noFetch  bool
	stderr   io.Writer
}

// prepareWorkdir resolves --source into a usable workspace directory
// and returns (workdir, freshCheckout, err). freshCheckout is true
// when the caller should re-install NER wheels after `uv sync`
// (which prunes anything outside uv.lock).
//
// Local-path source: returned unchanged, freshCheckout=false. The
// operator is responsible for fetching their own checkout.
//
// git+ source: clone (if cache empty) or fetch+checkout (if cache
// warm and !noFetch). Cache lives at:
//
//   - --cache-dir if non-empty
//   - else $PLENO_DLP_ANONYMIZE_CACHE if set
//   - else <os.UserCacheDir>/pleno-dlp/pleno-anonymize
//
// We MkdirAll with 0o700: the cache holds neither secrets nor scanned
// text, but the principle of least privilege keeps a future drift
// (someone reusing the dir for genuinely sensitive artifacts) safer.
func prepareWorkdir(ctx context.Context, in prepareInput) (workdir string, freshCheckout bool, err error) {
	if in.source == "" {
		return "", false, fmt.Errorf("--source is empty")
	}

	// Local path branch: passes through. We deliberately accept any
	// non-git+ form here (absolute or relative path) because users
	// running from a checkout reasonably expect either. We do
	// require the directory to exist — fail-fast beats failing
	// later inside `uv sync` with a less informative message.
	if !strings.HasPrefix(in.source, "git+") {
		abs, err := filepath.Abs(in.source)
		if err != nil {
			return "", false, fmt.Errorf("--source: %w", err)
		}
		fi, err := os.Stat(abs)
		if err != nil {
			return "", false, fmt.Errorf("--source %q: %w", in.source, err)
		}
		if !fi.IsDir() {
			return "", false, fmt.Errorf("--source %q: not a directory", in.source)
		}
		return abs, false, nil
	}

	cloneURL, err := stripGitURLPrefix(in.source)
	if err != nil {
		return "", false, err
	}

	cacheDir, err := resolveCacheDir(in.cacheDir)
	if err != nil {
		return "", false, err
	}
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return "", false, fmt.Errorf("create cache dir %q: %w", cacheDir, err)
	}

	dotgit := filepath.Join(cacheDir, ".git")
	_, statErr := os.Stat(dotgit)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		// Cold cache: full clone.
		if err := runGitClone(ctx, cloneURL, in.gitRef, cacheDir, in.stderr); err != nil {
			return "", false, err
		}
		return cacheDir, true, nil
	case statErr != nil:
		return "", false, fmt.Errorf("stat cache dir %q: %w", cacheDir, statErr)
	default:
		// Warm cache.
		if in.noFetch {
			return cacheDir, false, nil
		}
		ref := in.gitRef
		if ref == "" {
			ref = "main"
		}
		if err := runGitFetchCheckout(ctx, cacheDir, ref, in.stderr); err != nil {
			return "", false, err
		}
		// Treat any successful fetch+checkout as "fresh" for NER-wheel
		// purposes. Detecting whether the checkout actually moved would
		// require parsing `git rev-parse` output; the cost of a redundant
		// `uv pip install` (idempotent) is trivial vs. the cost of
		// missing a needed reinstall after a real ref change.
		return cacheDir, true, nil
	}
}

// stripGitURLPrefix removes the leading "git+" and any
// "#subdirectory=..." fragment from a uvx-style URL, returning the
// bare https URL git can clone. Handles `@ref` suffixes by leaving
// them in place — git clone --branch handles refs separately, and
// the upstream pip git+url syntax also tolerates either form.
func stripGitURLPrefix(s string) (string, error) {
	if !strings.HasPrefix(s, "git+") {
		return "", fmt.Errorf("--source %q: not a git+ URL", s)
	}
	s = strings.TrimPrefix(s, "git+")
	if i := strings.Index(s, "#"); i >= 0 {
		s = s[:i]
	}
	if _, err := url.Parse(s); err != nil {
		return "", fmt.Errorf("--source: parse URL: %w", err)
	}
	// Strip @ref if present after the path so git clone --branch
	// is the sole ref-control surface; mixing both is confusing.
	if slash := strings.LastIndex(s, "/"); slash >= 0 {
		if at := strings.LastIndex(s, "@"); at > slash {
			s = s[:at]
		}
	}
	return s, nil
}

// resolveCacheDir picks the cache root with the documented precedence:
// flag > env > os.UserCacheDir. Returns absolute path.
func resolveCacheDir(flagVal string) (string, error) {
	if flagVal != "" {
		return filepath.Abs(flagVal)
	}
	if env := os.Getenv("PLENO_DLP_ANONYMIZE_CACHE"); env != "" {
		return filepath.Abs(env)
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locate user cache dir: %w", err)
	}
	return filepath.Join(base, "pleno-dlp", "pleno-anonymize"), nil
}

// runGitClone shells out to `git clone --depth 1 [--branch ref] url dst`.
// We use --depth 1 because the cache is read-only from our perspective
// (we never commit or push) and a shallow clone keeps cold-start fast.
func runGitClone(ctx context.Context, url, ref, dst string, stderr io.Writer) error {
	args := []string{"clone", "--depth", "1"}
	if ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, url, dst)
	c := exec.CommandContext(ctx, gitBin, args...)
	c.Stdout = stderr
	c.Stderr = stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("git clone: %w", err)
	}
	return nil
}

// runGitFetchCheckout updates a warm cache to ref. We fetch shallowly
// to keep network cost bounded even when ref has moved far. Detached
// HEAD is acceptable — we never push from the cache.
func runGitFetchCheckout(ctx context.Context, dir, ref string, stderr io.Writer) error {
	fetch := exec.CommandContext(ctx, gitBin, "fetch", "--depth", "1", "origin", ref)
	fetch.Dir = dir
	fetch.Stdout = stderr
	fetch.Stderr = stderr
	if err := fetch.Run(); err != nil {
		return fmt.Errorf("git fetch: %w", err)
	}
	checkout := exec.CommandContext(ctx, gitBin, "checkout", "FETCH_HEAD")
	checkout.Dir = dir
	checkout.Stdout = stderr
	checkout.Stderr = stderr
	if err := checkout.Run(); err != nil {
		return fmt.Errorf("git checkout %q: %w", ref, err)
	}
	return nil
}

// runUVSync runs `uv sync --frozen --no-dev --package pleno-anonymize-server`
// inside dir. --frozen requires uv.lock to be authoritative (we never
// regenerate it from this side), --no-dev drops the dev dep group,
// and --package selects the workspace member (the server) so we don't
// pay for training-only deps.
func runUVSync(ctx context.Context, dir string, stderr io.Writer) error {
	c := exec.CommandContext(ctx, uvBin, "sync", "--frozen", "--no-dev", "--package", "pleno-anonymize-server")
	c.Dir = dir
	c.Stdout = stderr
	c.Stderr = stderr
	return c.Run()
}

// runUVPipInstallNERWheels installs the spaCy + NER model wheels that
// uv.lock cannot pin (they're hosted on GitHub Releases / Hugging
// Face, not PyPI). Mirrors the upstream Dockerfile lines 27–30.
func runUVPipInstallNERWheels(ctx context.Context, dir string, stderr io.Writer) error {
	for _, u := range nerWheelURLs {
		c := exec.CommandContext(ctx, uvBin, "pip", "install", u)
		c.Dir = dir
		c.Stdout = stderr
		c.Stderr = stderr
		if err := c.Run(); err != nil {
			return fmt.Errorf("uv pip install %s: %w", u, err)
		}
	}
	return nil
}

// buildPIIServerArgv constructs the argv for `uv run`. Pure function
// so the unit tests can drive it without touching exec.
//
// The uvicorn import target is `server.src.app:app`. This works
// because `child.Dir` is set to the workspace root (the cache dir);
// the upstream Dockerfile uses the same target with WORKDIR=/workspace.
// An earlier draft used `app:app` based on a misread of `pkgutil`
// output that landed on a packaged-wheel layout; with the workspace
// strategy we are NOT relying on packaged-wheel imports — the source
// tree is on disk and the import resolves through it.
func buildPIIServerArgv(uvBinary, host string, port int) []string {
	return []string{
		uvBinary,
		"run",
		"--no-sync", // preserve the NER wheels we just pip-installed
		"--package", "pleno-anonymize-server",
		"uvicorn",
		"server.src.app:app",
		"--host", host,
		"--port", strconv.Itoa(port),
	}
}
