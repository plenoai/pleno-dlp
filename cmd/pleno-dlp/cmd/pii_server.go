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

// pii-server is the foreground supervisor that materializes the
// pleno-anonymize HTTP server via uvx. Per ADR-0003 (the
// Docker-default revocation), the recommended runtime path is:
//
//	pleno-dlp scan --pii-engine=anonymize ...
//	  └─ pleno-dlp pii-server --port <ephemeral>            (this subcommand)
//	      └─ uvx --from <source> uvicorn server.src.app:app  (uv handles the venv)
//
// The user only needs `uvx` (the uv shipped helper) on PATH plus
// Python 3.12+. There is no Docker dependency anywhere in this flow.
//
// Direct invocation works too:
//
//	pleno-dlp pii-server --port 8080
//	pleno-dlp pii-server                # ephemeral port; the chosen
//	                                    # port is printed to stdout
//
// Network safety: --host is hard-restricted at flag parse to
// loopback / RFC1918 / link-local. 0.0.0.0 (and any other unspecified
// or public IP) is refused — pleno-dlp is a DLP tool and an
// accidentally exposed analyze endpoint would relay scanned text.

type piiServerFlags struct {
	port   int
	host   string
	gitRef string
	source string
}

var piiServerOpts piiServerFlags

// uvxBin is the executable used to spawn uv. Exposed as a package
// var so tests can substitute a fake script without putting one on
// PATH; production always uses the literal "uvx".
var uvxBin = "uvx"

// defaultPIIServerSource is the canonical uvx --from spec for the
// pleno-anonymize server module. Operators with a local checkout
// override via --source; downstream packagers can hard-pin via
// --git-ref to a release tag.
const defaultPIIServerSource = "git+https://github.com/plenoai/pleno-anonymize.git#subdirectory=server"

var piiServerCmd = &cobra.Command{
	Use:   "pii-server",
	Short: "Run the pleno-anonymize HTTP server (used by --pii-engine=anonymize)",
	Long: "pii-server foreground-spawns the pleno-anonymize HTTP server via uvx.\n" +
		"\n" +
		"Required runtime: uvx (uv) on PATH and Python 3.12+. No Docker required.\n" +
		"\n" +
		"Typical usage is indirect — 'pleno-dlp scan --pii-engine=anonymize' invokes\n" +
		"this subcommand on an ephemeral loopback port and tears it down at scan end.\n" +
		"Direct invocation is supported for ad-hoc local use:\n" +
		"\n" +
		"  pleno-dlp pii-server --port 8080\n" +
		"  pleno-dlp pii-server                  # ephemeral; resolved port is printed\n" +
		"  pleno-dlp pii-server --git-ref v0.5.0 # pin to a tag\n" +
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
		"git ref (tag/branch/sha) of pleno-anonymize to pin to; empty = whatever HEAD of main resolves to at uvx time")
	piiServerCmd.Flags().StringVar(&piiServerOpts.source, "source", defaultPIIServerSource,
		"uvx --from spec for the pleno-anonymize server module; override for a local checkout, e.g. --source /path/to/pleno-anonymize/server")
	Root.AddCommand(piiServerCmd)
}

func runPIIServer(cmd *cobra.Command, _ []string) error {
	if err := validatePIIServerHost(piiServerOpts.host); err != nil {
		return err
	}
	if _, err := exec.LookPath(uvxBin); err != nil {
		return fmt.Errorf("uvx not found on PATH (install uv: https://docs.astral.sh/uv/): %w", err)
	}

	port := piiServerOpts.port
	if port == 0 {
		p, err := pickEphemeralPort(piiServerOpts.host)
		if err != nil {
			return fmt.Errorf("allocate ephemeral port: %w", err)
		}
		port = p
	}

	source := applyGitRef(piiServerOpts.source, piiServerOpts.gitRef)
	argv := buildPIIServerArgv(uvxBin, source, piiServerOpts.host, port)

	// Print the resolved listening address before exec so a direct
	// caller can scrape it from stdout. The line shape is
	// intentionally stable: "pii-server: listening on HOST:PORT".
	// When the parent is the supervisor it doesn't need to scrape
	// (it already chose the port), so this line is harmless noise
	// in that path; for ad-hoc invocation it is the contract.
	fmt.Fprintf(cmd.OutOrStdout(), "pii-server: listening on %s:%d\n", piiServerOpts.host, port)

	// SIGTERM / SIGINT at this process should shut uvx down
	// gracefully. exec.CommandContext's default Cancel calls Kill,
	// which would leave a zombie uvicorn behind; we override to
	// SIGTERM and rely on WaitDelay to escalate.
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
		// error so `pleno-dlp pii-server` returns 0 when the user
		// hits Ctrl-C — a long-running foreground command that
		// exit-1's on every clean shutdown is friction for nothing.
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("uvx exec: %w", err)
	}
	return nil
}

// validatePIIServerHost rejects unspecified and public bind addresses.
// Loopback, RFC1918 (IsPrivate per Go stdlib, which covers RFC4193
// IPv6 ULA too), and link-local addresses are accepted.
//
// Hostnames are accepted only when they're literal "localhost"; we do
// not attempt DNS resolution here because operators' DNS could be
// hostile (split-horizon resolvers, /etc/hosts shenanigans) and the
// supervisor's own loopback gate already covers the call-site path.
// The point of this gate is to refuse the obvious-mistake values
// (0.0.0.0, the machine's LAN IP if someone copy-pastes from a
// general server tutorial) before the expensive uvx cold-start.
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
// uvx's own bind, but for this CLI's audience (single-developer or
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

// applyGitRef inserts a git ref into a uvx --from git+URL spec.
//
// Input shapes we support:
//
//	git+https://host/path.git                    + ref → git+https://host/path.git@ref
//	git+https://host/path.git#subdirectory=x     + ref → git+https://host/path.git@ref#subdirectory=x
//	/local/path                                  + ref → /local/path                  (silently dropped — no git for a path)
//	any non-git+ URL                             + ref → returned unchanged
//
// We deliberately do not validate ref against the remote — uvx
// surfaces a clear error if the ref doesn't exist, and adding our
// own resolver would mean shelling out to git just to fail twice.
func applyGitRef(source, ref string) string {
	if ref == "" {
		return source
	}
	if !strings.HasPrefix(source, "git+") {
		// Local checkouts ignore --git-ref; uvx doesn't take a ref
		// for a path source. Silent rather than erroring because the
		// supervisor can carry a stable --git-ref default while
		// individual operators flip --source to a local path.
		return source
	}
	// Split off any #fragment so we re-attach it after the @ref.
	frag := ""
	if i := strings.Index(source, "#"); i >= 0 {
		frag = source[i:]
		source = source[:i]
	}
	// Avoid double-@ if the caller already pinned a ref in --source.
	// We only strip an @ that appears AFTER the last `/` — that's
	// where a ref lives in the git+url format. An @ inside the
	// host's userinfo (`git+https://user@host/...`) sits before
	// the final `/` and must be preserved.
	if slash := strings.LastIndex(source, "/"); slash >= 0 {
		if at := strings.LastIndex(source, "@"); at > slash {
			source = source[:at]
		}
	}
	return source + "@" + ref + frag
}

// buildPIIServerArgv constructs the full uvx argv. Pure function so
// the unit tests can drive it without touching exec.
func buildPIIServerArgv(uvxBinary, source, host string, port int) []string {
	return []string{
		uvxBinary,
		"--from", source,
		"uvicorn",
		"server.src.app:app",
		"--host", host,
		"--port", strconv.Itoa(port),
	}
}
