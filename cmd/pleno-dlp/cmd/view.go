package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/plenoai/pleno-dlp/pkg/report"
)

var viewOpts struct {
	addr   string
	output string
}

var viewCmd = &cobra.Command{
	Use:   "view <report>...",
	Short: "Merge and browse pleno-dlp, SARIF, gitleaks, and trufflehog reports locally",
	Long: "Import one or more scanner reports, deduplicate findings across them, and\n" +
		"serve a self-contained HTML viewer on a loopback address.\n\n" +
		"Accepted inputs (auto-detected): pleno-dlp --format json/jsonl, SARIF 2.1.0\n" +
		"(pleno-dlp, gitleaks, or any producer), gitleaks JSON, trufflehog JSON/JSONL.\n" +
		"Raw secrets in gitleaks/trufflehog reports are hashed for dedup and redacted\n" +
		"before display; they are never served. Findings dedup by secret hash (when\n" +
		"known) plus location.\n\n" +
		"The server binds only to loopback (127.0.0.1, ::1, localhost). Use\n" +
		"--output to write the merged page to a file instead of serving it.",
	Args: cobra.MinimumNArgs(1),
	RunE: runView,
}

func init() {
	viewCmd.Flags().StringVar(&viewOpts.addr, "addr", "127.0.0.1:0", "loopback host:port to serve on (port 0 picks a free port)")
	viewCmd.Flags().StringVarP(&viewOpts.output, "output", "o", "", "write the merged HTML report to this file ('-' for stdout) instead of serving")
	Root.AddCommand(viewCmd)
}

func runView(cmd *cobra.Command, args []string) error {
	page, err := buildViewPage(args)
	if err != nil {
		return err
	}
	switch viewOpts.output {
	case "":
	case "-":
		_, err := cmd.OutOrStdout().Write(page)
		return err
	default:
		return os.WriteFile(viewOpts.output, page, 0o600)
	}
	if err := requireLoopback(viewOpts.addr); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", viewOpts.addr)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "pleno-dlp view: serving %d report(s) at http://%s/ (Ctrl-C to stop)\n", len(args), ln.Addr())
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer stop()
	return serveView(ctx, ln, page)
}

func buildViewPage(paths []string) ([]byte, error) {
	var all []report.Finding
	for _, p := range paths {
		fs, err := report.ImportFile(p)
		if err != nil {
			return nil, err
		}
		all = append(all, fs...)
	}
	var buf bytes.Buffer
	err := report.RenderHTML(&buf, report.Merge(all), report.Meta{
		Title:     "pleno-dlp view",
		Generator: "pleno-dlp " + toolVersion,
		Reports:   paths,
	})
	return buf.Bytes(), err
}

// requireLoopback rejects any bind address that is not a loopback host so
// the merged findings are never exposed on a network interface.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("--addr: %w", err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("--addr %q: view only binds to loopback addresses (127.0.0.1, ::1, localhost)", addr)
	}
	return nil
}

func serveView(ctx context.Context, ln net.Listener, page []byte) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Reject DNS-rebinding: only loopback Host headers are served.
		if err := requireLoopback(hostWithPort(r.Host)); err != nil {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		_, _ = w.Write(page)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		<-errc
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func hostWithPort(h string) string {
	if _, _, err := net.SplitHostPort(h); err == nil {
		return h
	}
	return net.JoinHostPort(strings.Trim(h, "[]"), "80")
}
