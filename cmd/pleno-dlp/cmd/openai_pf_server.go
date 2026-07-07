package cmd

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// openai-pf-server is the foreground supervisor that materializes the
// openai/privacy-filter wrapper at python/openaipf-server via uvx.
// Per ADR-0004 the runtime dependency is uv on PATH and Python 3.12+
// — no Docker, no separate repo. Unlike pii-server (which clones the
// pleno-anonymize workspace and runs `uv sync`), the openaipf wrapper
// is a single PEP 517 package, so uvx can install it directly with
// one --from spec and there is no workspace-sync step.
//
//	pleno-dlp scan --pii-engine=openai-pf ...
//	  └─ pleno-dlp openai-pf-server --port <ephemeral> --device <hint>
//	      └─ uvx --from "git+https://github.com/plenoai/pleno-dlp.git#subdirectory=python/openaipf-server[@ref]" \
//	             python -m openaipf_server --host <host> --port <port> --device <hint>
//
// Network safety: --host is hard-restricted at flag parse to loopback
// / RFC1918 / link-local. 0.0.0.0 (and any other unspecified or public
// IP) is refused — pleno-dlp is a DLP tool and an accidentally
// exposed analyze endpoint would relay scanned text (ADR-0001 hard
// rule).

type openAIPFServerFlags struct {
	port     int
	host     string
	device   string
	gitRef   string
	source   string
	logLevel string
}

var openAIPFServerOpts openAIPFServerFlags

// defaultOpenAIPFSource is the canonical uvx --from spec. The
// subdirectory= fragment is critical: pleno-dlp ships many things,
// only python/openaipf-server is pip-installable. Operators with a
// local checkout override via --source pointing at the package root.
const defaultOpenAIPFSource = "git+https://github.com/plenoai/pleno-dlp.git#subdirectory=python/openaipf-server"

var openAIPFServerCmd = &cobra.Command{
	Use:   "openai-pf-server",
	Short: "Run the openai/privacy-filter HTTP wrapper (used by --pii-engine=openai-pf)",
	Long: "openai-pf-server foreground-spawns the openai/privacy-filter wrapper via uvx.\n" +
		"\n" +
		"Required runtime: uv (https://docs.astral.sh/uv/) and Python 3.12+.\n" +
		"GPU is strongly recommended but not required — opf is a 1.5B-param model;\n" +
		"CPU inference works but is materially slower than GPU.\n" +
		"\n" +
		"Strategy: `uvx --from <source>` materializes the wrapper from the\n" +
		"pleno-dlp repo's python/openaipf-server subdirectory on first run; uv\n" +
		"caches the resolved environment so subsequent invocations are warm.\n" +
		"The wrapper itself downloads opf checkpoints from HuggingFace on first\n" +
		"use (multi-GB); /ready stays 503 until that completes.\n" +
		"\n" +
		"Typical usage is indirect — 'pleno-dlp scan --pii-engine=openai-pf'\n" +
		"invokes this subcommand on an ephemeral loopback port and tears it\n" +
		"down at scan end. Direct invocation is supported for ad-hoc local use:\n" +
		"\n" +
		"  pleno-dlp openai-pf-server --port 8080\n" +
		"  pleno-dlp openai-pf-server                       # ephemeral; resolved port printed\n" +
		"  pleno-dlp openai-pf-server --device cuda         # force GPU\n" +
		"  pleno-dlp openai-pf-server --git-ref v0.1.0      # pin to a tag\n" +
		"  pleno-dlp openai-pf-server --source /path/to/pleno-dlp/python/openaipf-server\n" +
		"\n" +
		"--host is restricted to loopback / RFC1918 / link-local addresses; binding\n" +
		"a public interface is refused so a DLP tool cannot accidentally relay scanned\n" +
		"text to a non-trusted listener.",
	Args: cobra.NoArgs,
	RunE: runOpenAIPFServer,
}

func init() {
	openAIPFServerCmd.Flags().IntVar(&openAIPFServerOpts.port, "port", 0,
		"port to bind (0 = auto-allocate an ephemeral loopback port; the resolved port is printed to stdout)")
	openAIPFServerCmd.Flags().StringVar(&openAIPFServerOpts.host, "host", "127.0.0.1",
		"bind address (loopback / RFC1918 / link-local only; refuses 0.0.0.0 and any public address)")
	openAIPFServerCmd.Flags().StringVar(&openAIPFServerOpts.device, "device", "auto",
		"inference device hint passed to opf: auto | cpu | cuda | mps")
	openAIPFServerCmd.Flags().StringVar(&openAIPFServerOpts.gitRef, "git-ref", "",
		"git ref (tag/branch/sha) of pleno-dlp to fetch the wrapper from; empty = main")
	openAIPFServerCmd.Flags().StringVar(&openAIPFServerOpts.source, "source", defaultOpenAIPFSource,
		"uvx --from spec. A `git+<URL>` value triggers uvx's remote fetch; an absolute filesystem path is treated as an existing wrapper checkout and used in-place.")
	openAIPFServerCmd.Flags().StringVar(&openAIPFServerOpts.logLevel, "log-level", "info",
		"uvicorn log level passed through to the wrapper: debug | info | warning | error | critical")
	Root.AddCommand(openAIPFServerCmd)
}

func runOpenAIPFServer(cmd *cobra.Command, _ []string) error {
	if err := validateOpenAIPFHost(openAIPFServerOpts.host); err != nil {
		return err
	}
	if err := validateOpenAIPFDevice(openAIPFServerOpts.device); err != nil {
		return err
	}
	if _, err := exec.LookPath(uvBin); err != nil {
		// uvx ships with uv. Looking up "uv" is the more reliable
		// presence check on PATH; uvx is invoked via its own absolute
		// path resolution by the child's argv.
		return fmt.Errorf("uv not found on PATH (install uv: https://docs.astral.sh/uv/): %w", err)
	}

	port := openAIPFServerOpts.port
	if port == 0 {
		p, err := pickEphemeralPort(openAIPFServerOpts.host)
		if err != nil {
			return fmt.Errorf("allocate ephemeral port: %w", err)
		}
		port = p
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	source := resolveOpenAIPFSource(openAIPFServerOpts.source, openAIPFServerOpts.gitRef)
	argv := buildOpenAIPFServerArgv(uvBin, source, openAIPFServerOpts.host, port, openAIPFServerOpts.device, openAIPFServerOpts.logLevel)

	// Stable "listening on HOST:PORT" line so direct invokers have a
	// parseable contract. The Go supervisor doesn't depend on parsing
	// it (it pre-allocates the port), but it's the documented signal
	// for human callers and the parity contract with pii-server.
	fmt.Fprintf(cmd.OutOrStdout(), "openai-pf-server: listening on %s:%d\n", openAIPFServerOpts.host, port)

	child := exec.CommandContext(ctx, argv[0], argv[1:]...)
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
		// Treat ctx-cancellation as a clean shutdown rather than an
		// error so `pleno-dlp openai-pf-server` returns 0 when the
		// user hits Ctrl-C — a long-running foreground command that
		// exit-1's on every clean shutdown is friction for nothing.
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("uvx run: %w", err)
	}
	return nil
}

// validateOpenAIPFHost rejects unspecified and public bind addresses.
// Loopback, RFC1918 (IsPrivate per Go stdlib, which covers RFC4193
// IPv6 ULA), and link-local are accepted. Logic is intentionally
// identical to validatePIIServerHost — same hard rule, same audience,
// same trust boundary — but kept as a separate function so a future
// per-engine relaxation doesn't have to fork mid-implementation.
func validateOpenAIPFHost(host string) error {
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

// validateOpenAIPFDevice enforces the closed device set the wrapper's
// argparse accepts. Validating here lets us fail fast with a clear
// error message before paying uvx's cold-start cost.
func validateOpenAIPFDevice(device string) error {
	switch device {
	case "auto", "cpu", "cuda", "mps":
		return nil
	default:
		return fmt.Errorf("--device %q: must be one of auto, cpu, cuda, mps", device)
	}
}

// resolveOpenAIPFSource appends @<ref> to a git+ source when --git-ref
// is set. uvx's `--from` accepts the `git+url@ref` form. Local
// filesystem paths pass through unchanged — operators using --source
// to point at a checkout are expected to have already checked out the
// ref they want.
func resolveOpenAIPFSource(source, ref string) string {
	if ref == "" {
		return source
	}
	if !strings.HasPrefix(source, "git+") {
		return source
	}
	// Strip any existing @ref the operator may have left in --source
	// so --git-ref is the authoritative knob. Be careful not to
	// strip an "@" inside a URL userinfo segment ("user@host"); a
	// ref-@ always comes after the LAST "/" in the URL PATH, which
	// is everything before the fragment marker.
	pathEnd := len(source)
	hash := strings.Index(source, "#")
	if hash >= 0 {
		pathEnd = hash
	}
	pathOnly := source[:pathEnd]
	fragment := source[pathEnd:]

	idx := -1
	if slash := strings.LastIndex(pathOnly, "/"); slash >= 0 {
		if at := strings.LastIndex(pathOnly, "@"); at > slash {
			idx = at
		}
	}
	var base string
	if idx >= 0 {
		base = pathOnly[:idx]
	} else {
		base = pathOnly
	}
	return base + "@" + ref + fragment
}

// buildOpenAIPFServerArgv constructs the uvx argv. Pure function so
// the unit tests can drive it without touching exec.
//
// The wrapper is invoked via `python -m openaipf_server` rather than
// the `openaipf-server` console_script because the module-form is
// more robust against entry-point packaging differences across uv
// versions and minor wrapper-side renames.
func buildOpenAIPFServerArgv(uvBinary, source, host string, port int, device, logLevel string) []string {
	return []string{
		uvBinary,
		"tool", "run", // uvx is `uv tool run`; using the long form keeps the spawn explicit
		"--from", source,
		"python", "-m", "openaipf_server",
		"--host", host,
		"--port", strconv.Itoa(port),
		"--device", device,
		"--log-level", logLevel,
	}
}
