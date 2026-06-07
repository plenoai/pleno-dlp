// Package redis detects Redis connection URIs that embed a password
// (`redis://:password@host:port` or `rediss://user:password@host`). The
// password span is the Raw secret; the full URI is RawV2 so reviewers
// can rotate without exposing host metadata in the primary view.
//
// Verify performs a RESP-protocol AUTH probe against the embedded host.
// For `rediss://` URIs the connection is wrapped with crypto/tls.
// The probe sends AUTH <password> (or AUTH <username> <password> for
// ACL-enabled instances), reads a single RESP reply, and issues QUIT.
// "+OK" or "-NOAUTH" (server requires no password) count as verified;
// "-WRONGPASS" / "-ERR invalid password" count as not verified (nil error).
package redis

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// rediss?:// — TLS variant included. Userinfo is required (`:` and `@`)
// because we only care about credential-bearing URIs. Password capture
// stops at `@`; the surrounding URL is captured as a separate group for
// RawV2.
var uriRe = regexp.MustCompile(`\b(rediss?://[^\s"'<>]*?:([^\s"'<>@/]+)@[^\s"'<>]+)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Redis }

func (Scanner) Keywords() []string { return []string{"redis://", "rediss://"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := uriRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		uri := string(m[1])
		password := string(m[2])
		if password == "" {
			continue
		}
		if _, dup := seen[uri]; dup {
			continue
		}
		seen[uri] = struct{}{}
		extra := map[string]string{}
		if u, err := url.Parse(uri); err == nil {
			if u.Host != "" {
				extra["host"] = u.Host
			}
			if u.User != nil {
				if name := u.User.Username(); name != "" {
					extra["user"] = name
				}
			}
		}
		res := detectors.Result{
			DetectorType: detectors.Redis,
			Raw:          []byte(password),
			RawV2:        []byte(uri),
			Redacted:     redact(password),
			ExtraData:    extra,
			Severity:     detectors.SeverityHigh,
		}
		if verify && len(res.RawV2) > 0 {
			verified, err := s.Verify(ctx, uri)
			res.Verified = verified
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// dialTimeout is the maximum time allowed for the TCP connection + AUTH
// exchange. Kept short to avoid blocking the scan pipeline.
const dialTimeout = 5 * time.Second

// Verify connects to the Redis instance embedded in the URI and performs
// an AUTH probe using the RESP protocol. The secret parameter is the full
// redis:// or rediss:// URI (the RawV2 value).
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	u, err := url.Parse(secret)
	if err != nil {
		return false, fmt.Errorf("redis: verify: parse URI: %w", err)
	}

	useTLS := u.Scheme == "rediss"

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if useTLS {
			port = "6380"
		} else {
			port = "6379"
		}
	}
	addr := net.JoinHostPort(host, port)

	password, _ := u.User.Password()
	username := u.User.Username()

	// Derive a deadline from the context or fall back to dialTimeout.
	deadline := time.Now().Add(dialTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	var conn net.Conn
	dialer := &net.Dialer{Timeout: dialTimeout}
	if useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			// The scanner must not refuse self-signed certs — many Redis
			// instances use internal CAs. InsecureSkipVerify is acceptable
			// here because we are probing *authentication*, not establishing
			// a trusted channel.
			InsecureSkipVerify: true, //nolint:gosec // verification probe, not data channel
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return false, err
	}
	defer func() {
		// Best-effort QUIT; ignore errors.
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write([]byte("*1\r\n$4\r\nQUIT\r\n"))
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(deadline)

	// Build RESP AUTH command.
	var cmd string
	if username != "" {
		cmd = fmt.Sprintf("*3\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
			len(username), username, len(password), password)
	} else {
		cmd = fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n",
			len(password), password)
	}

	if _, err := conn.Write([]byte(cmd)); err != nil {
		return false, err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	line = strings.TrimSpace(line)

	switch {
	case line == "+OK":
		return true, nil
	case strings.HasPrefix(line, "-NOAUTH"):
		// Server does not require a password — the credential is valid
		// (any password is accepted or no password is needed).
		return true, nil
	default:
		// -WRONGPASS, -ERR invalid password, or any other error.
		return false, nil
	}
}

func redact(t string) string {
	if len(t) <= 4 {
		return "..."
	}
	return t[:2] + "..."
}

// Compile-time interface checks.
var (
	_ detectors.Detector = Scanner{}
	_ detectors.Verifier = Scanner{}
)

func init() {
	detectors.Register(Scanner{})
}
