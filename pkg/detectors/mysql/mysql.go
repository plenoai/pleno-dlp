// Package mysql detects MySQL connection URIs that embed a password
// (`mysql://user:password@host` or `mysqlx://`). The password span is the
// Raw secret; the full URI is RawV2 so reviewers can rotate without exposing
// host metadata in the primary view.
//
// Verify performs a MySQL wire-protocol handshake against the embedded host.
// The probe reads the server greeting, computes the mysql_native_password
// hash (SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))), sends a
// HandshakeResponse41, and checks for OK_Packet (0x00) vs ERR_Packet (0xff).
// The connection is always closed with COM_QUIT after the auth exchange.
//
// No external driver dependencies are used — the implementation is pure
// Go stdlib (net, crypto/sha1, encoding/binary).
//
// Localhost / loopback / well-known example hosts are never probed.
package mysql

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var uriRe = regexp.MustCompile(`\b(mysqlx?://[^\s"'<>]*?:([^\s"'<>@/]+)@[^\s"'<>]+)`)

// skipVerifyHosts lists hosts that the Verify probe must never contact.
var skipVerifyHosts = map[string]struct{}{
	"localhost":        {},
	"127.0.0.1":        {},
	"::1":              {},
	"example.com":      {},
	"host.example.com": {},
}

// dialTimeout is the maximum time allowed for the TCP connection +
// handshake exchange. Kept short to avoid blocking the scan pipeline.
const dialTimeout = 5 * time.Second

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.MySQL }

func (Scanner) Keywords() []string { return []string{"mysql://", "mysqlx://"} }

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
			DetectorType: detectors.MySQL,
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

// Verify connects to the MySQL instance embedded in the URI and performs
// a full wire-protocol authentication handshake. The probe reads the server
// greeting, computes the mysql_native_password response, and checks for an
// OK_Packet. The secret parameter is the full mysql:// URI (the RawV2 value).
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	u, err := url.Parse(secret)
	if err != nil {
		return false, fmt.Errorf("mysql: verify: parse URI: %w", err)
	}

	hostname := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "mysqlx" {
			port = "33060"
		} else {
			port = "3306"
		}
	}

	if shouldSkipHost(hostname) {
		return false, nil
	}

	addr := net.JoinHostPort(hostname, port)

	password, _ := u.User.Password()
	username := u.User.Username()

	// Default database from URI path.
	database := strings.TrimPrefix(u.Path, "/")

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

	// Step 1: Read the server greeting (Initial Handshake Packet).
	greetBuf, err := readMySQLPacket(conn)
	if err != nil {
		return false, err
	}

	if len(greetBuf) < 1 {
		return false, fmt.Errorf("mysql: verify: empty greeting")
	}

	// ERR_Packet in greeting means the server refused the connection.
	if greetBuf[0] == 0xff {
		return false, nil
	}

	salt, err := parseGreeting(greetBuf)
	if err != nil {
		return false, err
	}

	// Step 2: Build and send HandshakeResponse41.
	authData := nativePasswordAuth(password, salt)
	resp := buildHandshakeResponse(username, authData, database)
	if err := writeMySQLPacket(conn, 1, resp); err != nil {
		return false, err
	}

	// Step 3: Read the auth response.
	authResp, err := readMySQLPacket(conn)
	if err != nil {
		return false, err
	}

	if len(authResp) < 1 {
		return false, nil
	}

	// Best-effort COM_QUIT.
	_ = writeMySQLPacket(conn, 0, []byte{0x01}) // COM_QUIT

	switch authResp[0] {
	case 0x00:
		// OK_Packet — authentication succeeded.
		return true, nil
	case 0xff:
		// ERR_Packet — wrong password or access denied.
		return false, nil
	case 0xfe:
		// AuthSwitchRequest — server wants a different auth plugin.
		// We only implement mysql_native_password; treat switch requests
		// as connectivity-confirmed but credential-unverifiable.
		return false, nil
	default:
		return false, nil
	}
}

// parseGreeting extracts the 20-byte auth salt from a MySQL Initial
// Handshake Packet (protocol version 10).
func parseGreeting(buf []byte) ([]byte, error) {
	if len(buf) < 1 || buf[0] != 10 {
		return nil, fmt.Errorf("mysql: verify: unsupported protocol version %d", buf[0])
	}

	// Skip protocol version (1 byte).
	pos := 1

	// Skip server version (null-terminated string).
	nullIdx := -1
	for i := pos; i < len(buf); i++ {
		if buf[i] == 0 {
			nullIdx = i
			break
		}
	}
	if nullIdx < 0 {
		return nil, fmt.Errorf("mysql: verify: malformed greeting (no version terminator)")
	}
	pos = nullIdx + 1

	// Skip connection id (4 bytes).
	if pos+4 > len(buf) {
		return nil, fmt.Errorf("mysql: verify: greeting too short for connection_id")
	}
	pos += 4

	// auth-plugin-data-part-1 (8 bytes).
	if pos+8 > len(buf) {
		return nil, fmt.Errorf("mysql: verify: greeting too short for auth_data_1")
	}
	salt := make([]byte, 0, 20)
	salt = append(salt, buf[pos:pos+8]...)
	pos += 8

	// Skip filler (1 byte).
	pos++

	// Skip capability_flags_lower (2 bytes).
	if pos+2 > len(buf) {
		return nil, fmt.Errorf("mysql: verify: greeting too short for capabilities")
	}
	pos += 2

	// Skip character_set (1 byte) + status_flags (2 bytes) +
	// capability_flags_upper (2 bytes) + auth_plugin_data_len (1 byte) +
	// reserved (10 bytes).
	if pos+16 > len(buf) {
		// Minimal greeting without the second salt part — use what we have.
		return salt, nil
	}
	pos += 16

	// auth-plugin-data-part-2 (max 13 bytes, 12 usable + null terminator).
	remaining := len(buf) - pos
	if remaining > 13 {
		remaining = 13
	}
	part2 := buf[pos : pos+remaining]
	// Strip trailing null if present.
	if len(part2) > 0 && part2[len(part2)-1] == 0 {
		part2 = part2[:len(part2)-1]
	}
	salt = append(salt, part2...)

	return salt, nil
}

// nativePasswordAuth computes the mysql_native_password hash:
// SHA1(password) XOR SHA1(salt + SHA1(SHA1(password)))
func nativePasswordAuth(password string, salt []byte) []byte {
	if password == "" {
		return nil
	}

	// stage1 = SHA1(password)
	s1 := sha1.Sum([]byte(password))

	// stage2 = SHA1(stage1)
	s2 := sha1.Sum(s1[:])

	// SHA1(salt + stage2)
	h := sha1.New()
	h.Write(salt)
	h.Write(s2[:])
	scramble := h.Sum(nil)

	// XOR stage1 with scramble
	result := make([]byte, sha1.Size)
	for i := 0; i < sha1.Size; i++ {
		result[i] = s1[i] ^ scramble[i]
	}
	return result
}

// buildHandshakeResponse builds a MySQL HandshakeResponse41 packet payload.
func buildHandshakeResponse(username string, authData []byte, database string) []byte {
	// Capability flags:
	//   CLIENT_PROTOCOL_41 (0x00000200)
	//   CLIENT_SECURE_CONNECTION (0x00008000)
	//   CLIENT_CONNECT_WITH_DB (0x00000008) — if database is set
	//   CLIENT_PLUGIN_AUTH (0x00080000)
	capFlags := uint32(0x00000200 | 0x00008000 | 0x00080000)
	if database != "" {
		capFlags |= 0x00000008
	}

	var buf []byte

	// capability_flags (4 bytes, little-endian)
	cf := make([]byte, 4)
	binary.LittleEndian.PutUint32(cf, capFlags)
	buf = append(buf, cf...)

	// max_packet_size (4 bytes)
	mp := make([]byte, 4)
	binary.LittleEndian.PutUint32(mp, 16*1024*1024)
	buf = append(buf, mp...)

	// character_set (1 byte) — utf8mb4 = 45
	buf = append(buf, 45)

	// reserved (23 bytes of zeros)
	buf = append(buf, make([]byte, 23)...)

	// username (null-terminated)
	buf = append(buf, []byte(username)...)
	buf = append(buf, 0x00)

	// auth_response_length (1 byte) + auth_response
	if authData != nil {
		buf = append(buf, byte(len(authData)))
		buf = append(buf, authData...)
	} else {
		buf = append(buf, 0x00)
	}

	// database (null-terminated, if CLIENT_CONNECT_WITH_DB)
	if database != "" {
		buf = append(buf, []byte(database)...)
		buf = append(buf, 0x00)
	}

	// auth_plugin_name (null-terminated)
	buf = append(buf, []byte("mysql_native_password")...)
	buf = append(buf, 0x00)

	return buf
}

// readMySQLPacket reads a single MySQL wire-protocol packet (4-byte header
// + payload). Returns the payload bytes.
func readMySQLPacket(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := readFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("mysql: read packet header: %w", err)
	}

	payloadLen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if payloadLen > 16*1024*1024 {
		return nil, fmt.Errorf("mysql: payload too large: %d", payloadLen)
	}

	payload := make([]byte, payloadLen)
	if _, err := readFull(conn, payload); err != nil {
		return nil, fmt.Errorf("mysql: read packet payload: %w", err)
	}
	return payload, nil
}

// writeMySQLPacket writes a MySQL wire-protocol packet with the given
// sequence number.
func writeMySQLPacket(conn net.Conn, seq byte, payload []byte) error {
	pLen := len(payload)
	hdr := []byte{
		byte(pLen),
		byte(pLen >> 8),
		byte(pLen >> 16),
		seq,
	}
	if _, err := conn.Write(append(hdr, payload...)); err != nil {
		return fmt.Errorf("mysql: write packet: %w", err)
	}
	return nil
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
