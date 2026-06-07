// Package postgres detects PostgreSQL connection URIs that embed a password
// (`postgres://user:password@host` or `postgresql://...`). The password span is
// the Raw secret; the full URI is RawV2 so reviewers can rotate without
// exposing host metadata in the primary view.
//
// Verify performs a PostgreSQL wire-protocol authentication probe against
// the embedded host. The probe sends a StartupMessage (protocol 3.0),
// reads the AuthenticationRequest, and responds to cleartext or MD5
// password challenges. An AuthenticationOk response marks the credential
// as verified; an ErrorResponse ('E') marks it as not verified. The
// connection is always terminated with an 'X' (Terminate) message.
//
// No external driver dependencies are used — the implementation is pure
// Go stdlib (net, crypto/md5, encoding/binary, encoding/hex).
//
// Localhost / loopback / well-known example hosts are never probed.
//
// Because the match is surfaced unverified, placeholder/example connection
// strings carry real false-positive risk (README quickstarts, docker-compose
// defaults, env-var templates in config files). FromData therefore applies a
// semantic gate on the captured password span: a case-insensitive sentinel
// denylist, a pure-template-marker exclusion (`${...}`, `{{...}}`, `%(...)s`,
// `<...>`), and a minimal Shannon-entropy floor that rejects degenerate runs
// like `aaaa`. The entropy floor is intentionally low: real short passwords
// such as `s3cr3t` sit around 2.25 bits/char, so a higher gate would discard
// genuine secrets. The denylist — not entropy — separates the literal
// `password`/`postgres`/`changeme` family from real credentials.
package postgres

import (
	"context"
	//nolint:gosec // MD5 is mandated by the PostgreSQL wire protocol, not used for security
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Both `postgres://` and `postgresql://` schemes are accepted. Userinfo is
// required (`:` and `@`).
var uriRe = regexp.MustCompile(`\b(postgres(?:ql)?://[^\s"'<>]*?:([^\s"'<>@/]+)@[^\s"'<>]+)`)

// passwordDenylist holds case-insensitive literal placeholder/sentinel values
// that appear in documentation and compose defaults rather than as real
// secrets. Entropy cannot separate these from genuine short passwords
// (`password`, `postgres`, `changeme` all sit at ~2.75 bits/char, the same band
// as a real `s3cr3t`), so an explicit denylist is the load-bearing filter.
var passwordDenylist = map[string]struct{}{
	"password":      {},
	"passwd":        {},
	"pass":          {},
	"postgres":      {},
	"postgresql":    {},
	"example":       {},
	"changeme":      {},
	"change_me":     {},
	"changethis":    {},
	"secret":        {},
	"mysecret":      {},
	"your_password": {},
	"yourpassword":  {},
	"placeholder":   {},
	"admin":         {},
	"root":          {},
	"test":          {},
	"hunter2":       {},
}

// templateMarkerRe matches a password span that is entirely an interpolation /
// template placeholder rather than a literal value: `${DB_PASS}`, `{{password}}`,
// `%(password)s`, or `<password>`. Such spans denote config templates where no
// literal secret is present.
var templateMarkerRe = regexp.MustCompile(`^(?:\$\{[^}]*\}|\{\{[^}]*\}\}|%\([^)]*\)s|<[^>]*>)$`)

// skipVerifyHosts lists hosts that the Verify probe must never contact.
var skipVerifyHosts = map[string]struct{}{
	"localhost":        {},
	"127.0.0.1":        {},
	"::1":              {},
	"example.com":      {},
	"host.example.com": {},
}

// minPasswordEntropy rejects only degenerate spans (e.g. `aaaa`, `0000`). It is
// deliberately well below the entropy of real short passwords so it never
// discards a genuine secret; the denylist handles dictionary placeholders.
const minPasswordEntropy = 1.0

// dialTimeout is the maximum time allowed for the TCP connection +
// authentication exchange. Kept short to avoid blocking the scan pipeline.
const dialTimeout = 5 * time.Second

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Postgres }

func (Scanner) Keywords() []string { return []string{"postgres://", "postgresql://"} }

// isPlaceholderPassword reports whether the captured password span is a
// documentation placeholder / template marker / degenerate value rather than a
// plausible literal secret.
func isPlaceholderPassword(password string) bool {
	if _, deny := passwordDenylist[strings.ToLower(password)]; deny {
		return true
	}
	if templateMarkerRe.MatchString(password) {
		return true
	}
	// Degenerate low-information spans (repeated chars) are not secrets.
	if !detectors.HasMinEntropy(password, minPasswordEntropy) {
		return true
	}
	return false
}

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
		// Suppress documentation placeholders / config templates: these are
		// surfaced unverified at SeverityHigh, so a literal `password` or a
		// `${DB_PASSWORD}` template would otherwise be pure noise.
		if isPlaceholderPassword(password) {
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
			DetectorType: detectors.Postgres,
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

// Verify connects to the PostgreSQL instance embedded in the URI and performs
// a wire-protocol authentication exchange. Supports trust (no password),
// cleartext password, and MD5 password authentication methods. The secret
// parameter is the full postgres:// URI (the RawV2 value).
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	u, err := url.Parse(secret)
	if err != nil {
		return false, fmt.Errorf("postgres: verify: parse URI: %w", err)
	}

	hostname := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "5432"
	}

	if shouldSkipHost(hostname) {
		return false, nil
	}

	addr := net.JoinHostPort(hostname, port)

	password, _ := u.User.Password()
	username := u.User.Username()
	if username == "" {
		username = "postgres"
	}

	database := strings.TrimPrefix(u.Path, "/")
	if database == "" {
		database = username
	}

	deadline := time.Now().Add(dialTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer func() {
		// Best-effort Terminate message.
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.Write(buildTerminate())
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(deadline)

	// Step 1: Send StartupMessage.
	startup := buildStartupMessage(username, database)
	if _, err := conn.Write(startup); err != nil {
		return false, err
	}

	// Step 2: Read server response.
	return handleAuthLoop(conn, username, password)
}

// handleAuthLoop reads PostgreSQL authentication messages and responds to
// cleartext / MD5 password challenges. Returns (true, nil) on successful
// authentication and (false, nil) when the server rejects the credential.
func handleAuthLoop(conn net.Conn, username, password string) (bool, error) {
	for {
		msgType, payload, err := readPgMessage(conn)
		if err != nil {
			return false, err
		}

		switch msgType {
		case 'R':
			// AuthenticationRequest
			if len(payload) < 4 {
				return false, fmt.Errorf("postgres: verify: auth message too short")
			}
			authType := binary.BigEndian.Uint32(payload[:4])

			switch authType {
			case 0:
				// AuthenticationOk — trust mode or successful auth.
				return true, nil
			case 3:
				// AuthenticationCleartextPassword — send password.
				if err := sendPasswordMessage(conn, password); err != nil {
					return false, err
				}
				// Continue loop to read the response.
			case 5:
				// AuthenticationMD5Password — 4-byte salt follows.
				if len(payload) < 8 {
					return false, fmt.Errorf("postgres: verify: MD5 auth message too short for salt")
				}
				salt := payload[4:8]
				md5pw := computeMD5Password(username, password, salt)
				if err := sendPasswordMessage(conn, md5pw); err != nil {
					return false, err
				}
				// Continue loop to read the response.
			default:
				// SCRAM-SHA-256 (10) or other auth method we don't support.
				// Connectivity is confirmed (we got an auth request from a real
				// PostgreSQL server) but we cannot verify the credential.
				return false, nil
			}

		case 'E':
			// ErrorResponse — authentication failed or server rejected.
			return false, nil

		default:
			// Unexpected message type — possibly a notice or negotiation.
			// For safety, continue reading up to one more message.
			return false, nil
		}
	}
}

// buildStartupMessage constructs a PostgreSQL v3.0 StartupMessage.
func buildStartupMessage(username, database string) []byte {
	// StartupMessage: Int32 length, Int32 protocol(196608 = 3.0),
	// then key=value pairs terminated by \0, then final \0.
	var params []byte
	params = append(params, []byte("user")...)
	params = append(params, 0x00)
	params = append(params, []byte(username)...)
	params = append(params, 0x00)
	params = append(params, []byte("database")...)
	params = append(params, 0x00)
	params = append(params, []byte(database)...)
	params = append(params, 0x00)
	params = append(params, 0x00) // final terminator

	totalLen := 4 + 4 + len(params) // length + protocol + params
	buf := make([]byte, 4+4)
	binary.BigEndian.PutUint32(buf[0:4], uint32(totalLen))
	binary.BigEndian.PutUint32(buf[4:8], 196608) // protocol version 3.0
	buf = append(buf, params...)
	return buf
}

// sendPasswordMessage sends a PostgreSQL PasswordMessage ('p').
func sendPasswordMessage(conn net.Conn, password string) error {
	// PasswordMessage: byte1 'p', Int32 length, String password\0
	payload := append([]byte(password), 0x00)
	totalLen := 4 + len(payload) // length includes itself
	buf := make([]byte, 1+4)
	buf[0] = 'p'
	binary.BigEndian.PutUint32(buf[1:5], uint32(totalLen))
	buf = append(buf, payload...)
	_, err := conn.Write(buf)
	return err
}

// computeMD5Password computes the PostgreSQL MD5-hashed password:
// "md5" + md5(md5(password + username) + salt)
func computeMD5Password(username, password string, salt []byte) string {
	// inner = md5(password + username)
	inner := md5.Sum([]byte(password + username)) //nolint:gosec // PostgreSQL wire protocol requires MD5
	innerHex := hex.EncodeToString(inner[:])

	// outer = md5(innerHex + salt)
	h := md5.New() //nolint:gosec // PostgreSQL wire protocol requires MD5
	h.Write([]byte(innerHex))
	h.Write(salt)
	outer := h.Sum(nil)

	return "md5" + hex.EncodeToString(outer)
}

// buildTerminate constructs a PostgreSQL Terminate message ('X').
func buildTerminate() []byte {
	buf := make([]byte, 5)
	buf[0] = 'X'
	binary.BigEndian.PutUint32(buf[1:5], 4) // length = 4 (includes itself)
	return buf
}

// readPgMessage reads a single PostgreSQL wire-protocol message (1-byte type
// + 4-byte length + payload). Returns the message type byte and the payload
// (excluding the type and length).
func readPgMessage(conn net.Conn) (byte, []byte, error) {
	hdr := make([]byte, 5) // 1 type + 4 length
	if _, err := readFull(conn, hdr); err != nil {
		return 0, nil, fmt.Errorf("postgres: read message header: %w", err)
	}

	msgType := hdr[0]
	msgLen := int(binary.BigEndian.Uint32(hdr[1:5])) // includes the 4 length bytes
	if msgLen < 4 || msgLen > 16*1024*1024 {
		return 0, nil, fmt.Errorf("postgres: invalid message length: %d", msgLen)
	}

	payloadLen := msgLen - 4
	if payloadLen == 0 {
		return msgType, nil, nil
	}

	payload := make([]byte, payloadLen)
	if _, err := readFull(conn, payload); err != nil {
		return 0, nil, fmt.Errorf("postgres: read message payload: %w", err)
	}

	return msgType, payload, nil
}

// readFull reads exactly len(buf) bytes from the connection.
func readFull(conn net.Conn, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		nn, err := conn.Read(buf[n:])
		n += nn
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// shouldSkipHost reports whether the given hostname must not be probed.
func shouldSkipHost(host string) bool {
	_, ok := skipVerifyHosts[strings.ToLower(host)]
	return ok
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
