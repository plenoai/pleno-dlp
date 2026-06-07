// Package mongodb detects MongoDB connection URIs that embed a password
// (`mongodb://user:password@host` or `mongodb+srv://user:password@host`).
// The password span is the Raw secret; the full URI is RawV2.
//
// Verify performs a lightweight connectivity probe against the embedded host.
// For standard `mongodb://` URIs, the detector dials the host:port over TCP,
// sends a minimal MongoDB OP_MSG isMaster handshake (no authentication), and
// checks for a valid server response. This confirms the endpoint is a real
// MongoDB instance without requiring a full driver or SCRAM-SHA-256 auth.
// ExtraData["verify_mode"]="connectivity" makes the probe scope transparent.
//
// For `mongodb+srv://` URIs, SRV DNS resolution and seed-list discovery
// require driver-level logic that would pull in heavy dependencies, so verify
// is skipped and ExtraData["srv_requires_driver"]="true" is set instead.
//
// Localhost / loopback / well-known example hosts are never probed.
package mongodb

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// `mongodb+srv://` requires escaping the `+` in regex.
var uriRe = regexp.MustCompile(`\b(mongodb(?:\+srv)?://[^\s"'<>]*?:([^\s"'<>@/]+)@[^\s"'<>]+)`)

// placeholderPasswords are documentation/template/quickstart values that
// produce syntactically-perfect MongoDB URIs but are never real secrets.
// Compared case-insensitively against the captured password span. The
// provider keyword gate is tight, but docker-compose and README snippets
// routinely embed these, so we drop them rather than emit SeverityHigh
// noise. (Verify is infeasible here — see package doc — so this denylist
// is the only available FP control.)
var placeholderPasswords = map[string]struct{}{
	"password":      {},
	"passwd":        {},
	"pass":          {},
	"changeme":      {},
	"example":       {},
	"secret":        {},
	"your_password": {},
	"your-password": {},
	"yourpassword":  {},
	"mypassword":    {},
	"test":          {},
	"admin":         {},
	"root":          {},
	"placeholder":   {},
	"xxx":           {},
	"redacted":      {},
}

// exampleHosts are well-known local/example deployment targets. A
// placeholder password pointed at one of these is conclusively a
// quickstart/compose snippet, not a real leaked credential.
var exampleHosts = map[string]struct{}{
	"localhost":        {},
	"127.0.0.1":        {},
	"mongo":            {},
	"db":               {},
	"::1":              {},
	"host.example.com": {},
}

// skipVerifyHosts lists hosts that the Verify probe must never contact.
var skipVerifyHosts = map[string]struct{}{
	"localhost":        {},
	"127.0.0.1":        {},
	"::1":              {},
	"example.com":      {},
	"host.example.com": {},
}

// minPasswordEntropy is a deliberately LOW Shannon-entropy floor
// (bits/char). It exists only to drop extreme-repetition placeholders such
// as "aaaa" (entropy 0) while retaining legitimate short real passwords —
// the existing "p4ss" fixture sits at ~1.50, so the floor is set well
// below it to avoid false negatives on valid short secrets.
const minPasswordEntropy = 1.2

// dialTimeout is the maximum time allowed for the TCP connection +
// handshake exchange. Kept short to avoid blocking the scan pipeline.
const dialTimeout = 5 * time.Second

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.MongoDB }

func (Scanner) Keywords() []string { return []string{"mongodb://", "mongodb+srv://"} }

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
		// url.Parse rejects `mongodb+srv` opaque, but the standard scheme
		// shape we accept here parses fine when we substitute mongodb+srv
		// for mongodbsrv. Use a simple manual host parse instead so we
		// don't depend on net/url quirks.
		if h, u := manualHostUser(uri); h != "" {
			extra["host"] = h
			if u != "" {
				extra["user"] = u
			}
		} else if pu, err := url.Parse(uri); err == nil {
			if pu.Host != "" {
				extra["host"] = pu.Host
			}
			if pu.User != nil {
				if name := pu.User.Username(); name != "" {
					extra["user"] = name
				}
			}
		}
		// FP control (hardening only — never widens the regex):
		//   1. drop documentation/template placeholder passwords outright;
		//   2. drop a low-entropy extreme-repetition password ("aaaa");
		//   3. belt-and-suspenders: a placeholder pointed at a well-known
		//      example/local host is conclusively a quickstart snippet.
		// (3) is subsumed by (1) today but is kept explicit so that
		// loosening the denylist later still suppresses compose snippets.
		if isPlaceholderPassword(password) {
			continue
		}
		if !detectors.HasMinEntropy(password, minPasswordEntropy) {
			continue
		}
		if host := stripPort(extra["host"]); isExampleHost(host) && isPlaceholderPassword(password) {
			continue
		}
		if strings.HasPrefix(uri, "mongodb+srv://") {
			extra["srv"] = "true"
		}
		res := detectors.Result{
			DetectorType: detectors.MongoDB,
			Raw:          []byte(password),
			RawV2:        []byte(uri),
			Redacted:     redact(password),
			ExtraData:    extra,
			Severity:     detectors.SeverityHigh,
		}
		if verify && len(res.RawV2) > 0 {
			if extra["srv"] == "true" {
				// SRV discovery requires DNS SRV + TXT lookups plus seed-list
				// parsing — driver-level logic we deliberately avoid.
				extra["srv_requires_driver"] = "true"
			} else {
				verified, err := s.Verify(ctx, uri)
				res.Verified = verified
				res.VerificationErr = err
				if verified {
					extra["verify_mode"] = "connectivity"
				}
			}
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// Verify connects to the MongoDB instance embedded in the URI and performs
// a lightweight OP_MSG isMaster handshake to confirm the host is a real
// MongoDB server. This is a connectivity-only probe — credentials are NOT
// verified (SCRAM-SHA-256 would require a full driver). The secret
// parameter is the full mongodb:// URI (the RawV2 value).
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	host, _ := manualHostUser(secret)
	if host == "" {
		u, err := url.Parse(secret)
		if err != nil {
			return false, fmt.Errorf("mongodb: verify: parse URI: %w", err)
		}
		host = u.Host
	}

	hostname := stripPort(host)
	port := extractPort(host)
	if port == "" {
		port = "27017"
	}

	if shouldSkipHost(hostname) {
		return false, nil
	}

	addr := net.JoinHostPort(hostname, port)

	deadline := time.Now().Add(dialTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(deadline)

	// Send a minimal MongoDB OP_MSG isMaster command.
	// Wire protocol: MsgHeader (16 bytes) + OP_MSG body.
	msg := buildIsMasterMsg()

	if _, err := conn.Write(msg); err != nil {
		return false, err
	}

	// Read response header (16 bytes minimum).
	hdr := make([]byte, 16)
	if _, err := readFull(conn, hdr); err != nil {
		return false, err
	}

	// Parse message length from the first 4 bytes (little-endian int32).
	msgLen := int(binary.LittleEndian.Uint32(hdr[:4]))
	if msgLen < 16 || msgLen > 48*1024*1024 {
		// Not a valid MongoDB response.
		return false, nil
	}

	// Read the rest of the response to confirm it's valid.
	remaining := msgLen - 16
	if remaining > 0 {
		body := make([]byte, remaining)
		if _, err := readFull(conn, body); err != nil {
			return false, err
		}
	}

	// If we got a well-formed MongoDB wire-protocol response, the host
	// is a real MongoDB instance.
	return true, nil
}

// buildIsMasterMsg constructs a minimal MongoDB OP_MSG (opcode 2013)
// carrying the BSON document {isMaster: 1, $db: "admin"}.
func buildIsMasterMsg() []byte {
	// BSON document: {isMaster: 1, $db: "admin"}
	//
	// isMaster field: type 0x10 (int32), name "isMaster\0", value 1
	// $db field:      type 0x02 (string), name "$db\0", value "admin\0"
	//
	// BSON encoding:
	//   int32 doc_length
	//   0x10 "isMaster\0" int32(1)
	//   0x02 "$db\0" int32(6) "admin\0"
	//   0x00 (terminator)

	isMasterField := []byte{0x10} // int32 type
	isMasterField = append(isMasterField, []byte("isMaster\x00")...)
	isMasterField = append(isMasterField, 0x01, 0x00, 0x00, 0x00) // int32 value = 1

	dbField := []byte{0x02} // string type
	dbField = append(dbField, []byte("$db\x00")...)
	dbStrLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(dbStrLen, 6) // length of "admin\0"
	dbField = append(dbField, dbStrLen...)
	dbField = append(dbField, []byte("admin\x00")...)

	docBody := append(isMasterField, dbField...)
	docBody = append(docBody, 0x00) // BSON terminator

	docLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(docLen, uint32(4+len(docBody)))
	bsonDoc := append(docLen, docBody...)

	// OP_MSG body: flagBits (uint32) + kind 0 (body) + BSON document
	var opMsgBody []byte
	opMsgBody = append(opMsgBody, 0x00, 0x00, 0x00, 0x00) // flagBits = 0
	opMsgBody = append(opMsgBody, 0x00)                    // section kind 0 (body)
	opMsgBody = append(opMsgBody, bsonDoc...)

	// MsgHeader: messageLength (int32) + requestID (int32) + responseTo (int32) + opCode (int32)
	totalLen := 16 + len(opMsgBody)
	msg := make([]byte, 16)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))   // messageLength
	binary.LittleEndian.PutUint32(msg[4:8], 1)                  // requestID
	binary.LittleEndian.PutUint32(msg[8:12], 0)                 // responseTo
	binary.LittleEndian.PutUint32(msg[12:16], 2013)             // opCode = OP_MSG

	return append(msg, opMsgBody...)
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

// manualHostUser splits `scheme://user:password@host[/path]` into (host,
// user) without depending on net/url's handling of `+srv`.
func manualHostUser(uri string) (string, string) {
	idx := strings.Index(uri, "://")
	if idx < 0 {
		return "", ""
	}
	rest := uri[idx+3:]
	at := strings.Index(rest, "@")
	if at < 0 {
		return "", ""
	}
	userinfo := rest[:at]
	hostpath := rest[at+1:]
	host := hostpath
	if slash := strings.Index(hostpath, "/"); slash >= 0 {
		host = hostpath[:slash]
	}
	if q := strings.Index(host, "?"); q >= 0 {
		host = host[:q]
	}
	user := ""
	if colon := strings.Index(userinfo, ":"); colon >= 0 {
		user = userinfo[:colon]
	}
	return host, user
}

func isPlaceholderPassword(pw string) bool {
	_, ok := placeholderPasswords[strings.ToLower(pw)]
	return ok
}

func isExampleHost(host string) bool {
	_, ok := exampleHosts[strings.ToLower(host)]
	return ok
}

// shouldSkipHost reports whether the given hostname must not be probed.
func shouldSkipHost(host string) bool {
	_, ok := skipVerifyHosts[strings.ToLower(host)]
	return ok
}

// stripPort removes a trailing `:port` so host comparisons match
// regardless of whether the URI pinned a port (e.g. `localhost:27017`).
func stripPort(host string) string {
	if colon := strings.LastIndex(host, ":"); colon >= 0 {
		return host[:colon]
	}
	return host
}

// extractPort returns the port portion of a host:port string, or "".
func extractPort(host string) string {
	if colon := strings.LastIndex(host, ":"); colon >= 0 {
		return host[colon+1:]
	}
	return ""
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
