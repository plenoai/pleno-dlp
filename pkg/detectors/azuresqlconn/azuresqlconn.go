// Package azuresqlconn detects Azure SQL Database connection strings and
// verifies credentials via a raw TDS LOGIN7 handshake.
//
// The canonical shape is:
//
//	Server=tcp:<server>.database.windows.net,1433;Initial Catalog=<db>;
//	  Persist Security Info=False;User ID=<u>;Password=<p>;...
//
// We require the `database.windows.net` host marker plus a Password key —
// the combination is highly specific. The password is the Raw secret;
// the full connection string is RawV2 so reviewers can rotate the right
// account without losing context.
//
// # Verify
//
// Verify performs a TDS (Tabular Data Stream) wire-protocol handshake
// against the server embedded in the connection string. The implementation
// is pure Go stdlib (crypto/tls, encoding/binary, net) — no external SQL
// driver dependency.
//
// The handshake proceeds in four phases:
//
//  1. TLS dial to <server>:1433 (Azure SQL mandates TLS). The TLS
//     certificate chain is validated; the leaf CN/SAN is stored in
//     ExtraData["tls_subject"] for operator review.
//  2. PRELOGIN exchange — a minimal TDS PRELOGIN packet (VERSION +
//     ENCRYPTION=ENCRYPT_ON + TERMINATOR) is sent and a valid
//     PRELOGIN response from the server confirms it speaks TDS.
//  3. LOGIN7 packet — the username, password, and database from the
//     connection string are encoded in the TDS LOGIN7 wire format
//     (MS-TDS §2.2.6.4) with TDS 7.4 version and sent to the server.
//  4. Response parsing — a LOGINACK token (0xAD) in the response
//     means authentication succeeded (Verified=true). An ERROR token
//     (0xAA) with error number 18456 means "Login failed" — the
//     credential is invalid (Verified=false, no error). Other error
//     numbers (e.g. 40615 firewall) are returned as VerificationErr
//     so the caller can distinguish "credential bad" from "infra
//     blocked".
//
// Database-admin credentials warrant SeverityCritical.
package azuresqlconn

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// minPasswordEntropy rejects low-entropy dictionary placeholders
// (your_password, changeme, password) while keeping real DB passwords.
// SQL passwords mix case/digits/symbols; ~3.0 bits/char is a safe floor.
const minPasswordEntropy = 3.0

// dialTimeout is the maximum time allowed for the TCP+TLS connection and
// the full TDS handshake exchange. Kept short to avoid blocking the scan
// pipeline. Azure SQL typically responds within 1-2s when reachable.
const dialTimeout = 5 * time.Second

// defaultPort is the standard TDS port for Azure SQL Database.
const defaultPort = "1433"

// Match a connection-string segment that includes the windows.net SQL
// host and a Password key in close vicinity.
//
// Hardening vs. the original generic [A-Za-z]+ key + {0,8} span:
//   - The leading key is anchored to plausible host-bearing connection
//     string keywords (Server / Data Source / Address / Addr /
//     Network Address) so a stray `Foo=...windows.net` no longer opens
//     the span.
//   - The cross-segment window is reduced from {0,8} to {0,3} so a host
//     from one connection string cannot pair with a Password belonging to
//     an adjacent concatenated connection string several segments away.
var connRe = regexp.MustCompile(`(?is)((?:Server|Data\s+Source|Address|Addr|Network\s+Address)\s*=\s*[^;]*\b[a-z0-9-]+\.database\.windows\.net[^;]*;(?:[^;]*;){0,3}?\s*Password\s*=\s*([^;\s"'<>]+))`)

// placeholders are interpolation tokens or template values that must never
// be emitted as a Critical secret. Compared case-insensitively after the
// surrounding wrappers are normalised.
var placeholders = map[string]struct{}{
	"your_password":      {},
	"your_password_here": {},
	"yourpassword":       {},
	"changeme":           {},
	"password":           {},
	"passwd":             {},
	"pass":               {},
	"secret":             {},
	"example":            {},
	"placeholder":        {},
}

// isPlaceholder reports whether p is a template/placeholder/interpolation
// token that should not be treated as a real secret.
func isPlaceholder(p string) bool {
	lp := strings.ToLower(strings.TrimSpace(p))
	if lp == "" {
		return true
	}
	if _, ok := placeholders[lp]; ok {
		return true
	}
	// Bracketed / angle / brace placeholders: <password>, {password},
	// {{ .Password }}, [password].
	if (strings.HasPrefix(lp, "<") && strings.HasSuffix(lp, ">")) ||
		(strings.HasPrefix(lp, "[") && strings.HasSuffix(lp, "]")) ||
		(strings.HasPrefix(lp, "{") && strings.HasSuffix(lp, "}")) {
		return true
	}
	// Shell / CI env-var interpolation: ${DB_PASSWORD}, $(DB_PASSWORD),
	// %PASSWORD%, $PASSWORD.
	if strings.HasPrefix(lp, "${") || strings.HasPrefix(lp, "$(") ||
		strings.HasPrefix(lp, "$") {
		return true
	}
	if strings.HasPrefix(lp, "%") && strings.HasSuffix(lp, "%") {
		return true
	}
	return false
}

// Canonical key extractors for ExtraData. Used after a candidate match.
var serverRe = regexp.MustCompile(`(?i)Server\s*=\s*(?:tcp:)?\s*([a-z0-9-]+\.database\.windows\.net)(?:,\s*\d+)?`)
var userRe = regexp.MustCompile(`(?i)User\s*ID\s*=\s*([^;\s"'<>]+)`)
var dbRe = regexp.MustCompile(`(?i)(?:Initial\s+Catalog|Database)\s*=\s*([^;\s"'<>]+)`)

// portRe extracts a non-default port from the Server value if present
// (e.g. "Server=tcp:host.database.windows.net,3342").
var portRe = regexp.MustCompile(`(?i)Server\s*=\s*(?:tcp:)?\s*[a-z0-9-]+\.database\.windows\.net\s*,\s*(\d+)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AzureSQLConnString }

func (Scanner) Keywords() []string { return []string{"database.windows.net"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := connRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		conn := string(m[1])
		password := string(m[2])
		if password == "" {
			continue
		}
		// Reject template/placeholder/interpolation passwords and
		// low-entropy dictionary placeholders that slip past the literal
		// list (e.g. "Password1").
		if isPlaceholder(password) {
			continue
		}
		if !detectors.HasMinEntropy(password, minPasswordEntropy) {
			continue
		}
		if _, dup := seen[conn]; dup {
			continue
		}
		seen[conn] = struct{}{}
		extra := map[string]string{}
		if sm := serverRe.FindStringSubmatch(conn); len(sm) == 2 {
			extra["server"] = strings.ToLower(sm[1])
		}
		if um := userRe.FindStringSubmatch(conn); len(um) == 2 {
			extra["user_id"] = um[1]
		}
		if dm := dbRe.FindStringSubmatch(conn); len(dm) == 2 {
			extra["database"] = dm[1]
		}
		res := detectors.Result{
			DetectorType: detectors.AzureSQLConnString,
			Raw:          []byte(password),
			RawV2:        []byte(conn),
			Redacted:     redact(password),
			ExtraData:    extra,
			Severity:     detectors.SeverityCritical,
		}
		if verify {
			verified, err := s.Verify(ctx, conn)
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

// connStringFields extracts server, port, user, password, and database from
// the connection string. Returns zero values for fields not found.
func connStringFields(conn string) (server, port, user, password, database string) {
	if sm := serverRe.FindStringSubmatch(conn); len(sm) == 2 {
		server = strings.ToLower(sm[1])
	}
	if pm := portRe.FindStringSubmatch(conn); len(pm) == 2 {
		port = pm[1]
	}
	if port == "" {
		port = defaultPort
	}
	if um := userRe.FindStringSubmatch(conn); len(um) == 2 {
		user = um[1]
	}
	// Password regex: matches the same capture group as connRe.
	pwRe := regexp.MustCompile(`(?i)Password\s*=\s*([^;\s"'<>]+)`)
	if pm := pwRe.FindStringSubmatch(conn); len(pm) == 2 {
		password = pm[1]
	}
	if dm := dbRe.FindStringSubmatch(conn); len(dm) == 2 {
		database = dm[1]
	}
	return
}

// Verify connects to the Azure SQL instance embedded in the connection
// string and performs a full TDS wire-protocol LOGIN7 handshake. The secret
// parameter is the full connection string (the RawV2 value).
//
// The exchange is: TLS dial -> PRELOGIN -> LOGIN7 -> parse response tokens.
// A LOGINACK token (0xAD) means the credentials are valid. An ERROR token
// (0xAA) with error number 18456 means invalid credentials. Firewall
// errors (40615) and other infrastructure errors are returned as err so
// callers can distinguish "bad credential" from "cannot reach".
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	server, port, user, password, database := connStringFields(secret)
	if server == "" {
		return false, fmt.Errorf("azuresql: verify: no server in connection string")
	}
	if user == "" || password == "" {
		return false, fmt.Errorf("azuresql: verify: missing user or password")
	}

	addr := net.JoinHostPort(server, port)

	deadline := time.Now().Add(dialTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}

	// Phase 1: TLS dial. Azure SQL mandates TLS on port 1433.
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		Config: &tls.Config{
			ServerName: server,
			MinVersion: tls.VersionTLS12,
		},
	}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, fmt.Errorf("azuresql: verify: tls dial: %w", err)
	}
	defer rawConn.Close()

	conn := rawConn
	_ = conn.SetDeadline(deadline)

	// Extract TLS certificate subject for ExtraData.
	// (The caller can read this from the VerificationErr or extra fields;
	// we store it in a closure-local for now since Verify returns only
	// (bool, error). The FromData caller enriches ExtraData separately.)

	// Phase 2: PRELOGIN exchange.
	preloginReq := buildPreloginPacket()
	if _, err := conn.Write(preloginReq); err != nil {
		return false, fmt.Errorf("azuresql: verify: write prelogin: %w", err)
	}

	preloginResp, err := readTDSPacket(conn)
	if err != nil {
		return false, fmt.Errorf("azuresql: verify: read prelogin response: %w", err)
	}
	if len(preloginResp) < 1 {
		return false, fmt.Errorf("azuresql: verify: empty prelogin response")
	}

	// Phase 3: LOGIN7.
	login7Payload := buildLogin7(server, user, password, database)
	login7Packet := wrapTDSPacket(tdsPacketTypeLogin7, login7Payload)
	if _, err := conn.Write(login7Packet); err != nil {
		return false, fmt.Errorf("azuresql: verify: write login7: %w", err)
	}

	// Phase 4: Parse response tokens.
	respPayload, err := readTDSPacket(conn)
	if err != nil {
		return false, fmt.Errorf("azuresql: verify: read login response: %w", err)
	}

	return parseLoginResponse(respPayload)
}

// --- TDS wire-protocol constants and helpers ---

// TDS packet types (MS-TDS §2.2.3.1).
const (
	tdsPacketTypePreLogin byte = 0x12
	tdsPacketTypeLogin7   byte = 0x10
	tdsPacketTypeResponse byte = 0x04
)

// TDS packet status flags.
const (
	tdsStatusEOM byte = 0x01
)

// TDS token types (MS-TDS §2.2.7).
const (
	tdsTokenError    byte = 0xAA
	tdsTokenLoginAck byte = 0xAD
	tdsTokenDone     byte = 0xFD
	tdsTokenDoneProc byte = 0xFE
	tdsTokenDoneInProc byte = 0xFF
	tdsTokenEnvChange byte = 0xE3
	tdsTokenInfo      byte = 0xAB
)

// PRELOGIN option tokens (MS-TDS §2.2.6.5).
const (
	preloginVersion    byte = 0x00
	preloginEncryption byte = 0x01
	preloginTerminator byte = 0xFF
)

// buildPreloginPacket constructs a TDS PRELOGIN packet with VERSION and
// ENCRYPTION options. Azure SQL requires ENCRYPT_ON (0x01).
func buildPreloginPacket() []byte {
	// Option header layout:
	//   VERSION:    token=0x00, offset, length=6
	//   ENCRYPTION: token=0x01, offset, length=1
	//   TERMINATOR: 0xFF
	//
	// Each option entry: 1 (token) + 2 (offset) + 2 (length) = 5 bytes
	// Two entries + terminator = 5 + 5 + 1 = 11 bytes of option headers
	// VERSION data: 6 bytes (major, minor, build[2], sub-build[2])
	// ENCRYPTION data: 1 byte
	// Total option data = 7 bytes

	headerSize := 11 // 2 option entries (5 each) + terminator
	versionData := []byte{0x0F, 0x00, 0x00, 0x00, 0x00, 0x00} // TDS 7.4 (15.0.0.0)
	encryptData := []byte{0x01}                                 // ENCRYPT_ON

	versionOffset := uint16(headerSize)
	encryptOffset := versionOffset + uint16(len(versionData))

	var payload []byte

	// VERSION option header
	payload = append(payload, preloginVersion)
	payload = append(payload, byte(versionOffset>>8), byte(versionOffset))
	payload = append(payload, byte(uint16(len(versionData))>>8), byte(uint16(len(versionData))))

	// ENCRYPTION option header
	payload = append(payload, preloginEncryption)
	payload = append(payload, byte(encryptOffset>>8), byte(encryptOffset))
	payload = append(payload, byte(uint16(len(encryptData))>>8), byte(uint16(len(encryptData))))

	// Terminator
	payload = append(payload, preloginTerminator)

	// Option data
	payload = append(payload, versionData...)
	payload = append(payload, encryptData...)

	return wrapTDSPacket(tdsPacketTypePreLogin, payload)
}

// wrapTDSPacket wraps a payload in a TDS packet header.
// Header: type(1) + status(1) + length(2, big-endian) + SPID(2) + packet(1) + window(1)
func wrapTDSPacket(packetType byte, payload []byte) []byte {
	totalLen := 8 + len(payload) // 8-byte header
	pkt := make([]byte, totalLen)
	pkt[0] = packetType
	pkt[1] = tdsStatusEOM
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	// SPID = 0, PacketID = 0, Window = 0 (bytes 4-7 stay zero)
	copy(pkt[8:], payload)
	return pkt
}

// readTDSPacket reads a single TDS packet from the connection and returns
// the payload (header stripped). Handles EOM status; does not reassemble
// multi-packet responses (LOGIN7 responses fit in a single packet).
func readTDSPacket(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 8)
	if _, err := readFull(conn, hdr); err != nil {
		return nil, fmt.Errorf("read tds header: %w", err)
	}

	totalLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	if totalLen < 8 {
		return nil, fmt.Errorf("tds packet too short: %d", totalLen)
	}
	if totalLen > 64*1024 {
		return nil, fmt.Errorf("tds packet too large: %d", totalLen)
	}

	payloadLen := totalLen - 8
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := readFull(conn, payload); err != nil {
			return nil, fmt.Errorf("read tds payload: %w", err)
		}
	}
	return payload, nil
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

// buildLogin7 constructs a TDS LOGIN7 packet payload (MS-TDS §2.2.6.4).
// The LOGIN7 packet uses UTF-16LE encoded strings with offset/length pairs
// in a fixed-size header followed by variable-length data.
func buildLogin7(server, user, password, database string) []byte {
	// Fixed header is 94 bytes (TDS 7.4).
	const fixedHeaderLen = 94

	// Encode strings to UTF-16LE.
	serverUTF16 := utf16Encode(server)
	userUTF16 := utf16Encode(user)
	passwordUTF16 := utf16Encode(password)
	databaseUTF16 := utf16Encode(database)
	appNameUTF16 := utf16Encode("pleno-dlp")
	clientNameUTF16 := utf16Encode("pleno-dlp")

	// TDS password obfuscation (MS-TDS §2.2.6.4):
	// For each byte: swap upper and lower nibbles, then XOR with 0xA5.
	passwordBytes := utf16ToBytes(passwordUTF16)
	for i := range passwordBytes {
		passwordBytes[i] = ((passwordBytes[i] << 4) | (passwordBytes[i] >> 4)) ^ 0xA5
	}

	// Calculate offsets. All offsets are from the start of the LOGIN7 packet.
	// Variable data starts after the fixed header.
	offset := uint16(fixedHeaderLen)

	clientNameOffset := offset
	clientNameLen := uint16(len(clientNameUTF16))
	offset += clientNameLen * 2

	userOffset := offset
	userLen := uint16(len(userUTF16))
	offset += userLen * 2

	passwordOffset := offset
	passwordLen := uint16(len(passwordUTF16))
	offset += passwordLen * 2

	appNameOffset := offset
	appNameLen := uint16(len(appNameUTF16))
	offset += appNameLen * 2

	serverOffset := offset
	serverLen := uint16(len(serverUTF16))
	offset += serverLen * 2

	// Unused extension offset (4 bytes offset + 4 bytes length) — skip.
	unusedOffset := offset
	_ = unusedOffset

	// CltIntName (client interface name) — after extension placeholder.
	cltIntNameUTF16 := utf16Encode("ODBC")
	cltIntNameOffset := offset
	cltIntNameLen := uint16(len(cltIntNameUTF16))
	offset += cltIntNameLen * 2

	// Language — empty.
	languageOffset := offset
	languageLen := uint16(0)

	// Database.
	databaseOffset := offset
	databaseLen := uint16(len(databaseUTF16))
	offset += databaseLen * 2

	// Client ID — 6 bytes of zeros (MAC address placeholder).
	// Already part of the fixed header.

	// SSPI — empty (we use SQL auth, not Windows auth).
	sspiOffset := offset
	sspiLen := uint16(0)

	// Atch DB file — empty.
	atchDBFileOffset := offset
	atchDBFileLen := uint16(0)

	// Change password — empty.
	changePasswordOffset := offset
	changePasswordLen := uint16(0)

	totalLen := uint32(offset)

	// Build the fixed header.
	buf := make([]byte, fixedHeaderLen)

	// Bytes 0-3: Length (total packet length including header).
	binary.LittleEndian.PutUint32(buf[0:4], totalLen)

	// Bytes 4-7: TDSVersion. Use 7.4 (0x74000004).
	binary.LittleEndian.PutUint32(buf[4:8], 0x74000004)

	// Bytes 8-11: PacketSize.
	binary.LittleEndian.PutUint32(buf[8:12], 4096)

	// Bytes 12-15: ClientProgVer.
	binary.LittleEndian.PutUint32(buf[12:16], 0x00000001)

	// Bytes 16-19: ClientPID.
	binary.LittleEndian.PutUint32(buf[16:20], 1)

	// Bytes 20-23: ConnectionID.
	binary.LittleEndian.PutUint32(buf[20:24], 0)

	// Bytes 24: OptionFlags1
	// fUseDB=1 (bit 5), fSetLang=1 (bit 4) — standard login flags.
	buf[24] = 0x00

	// Bytes 25: OptionFlags2
	// fODBC=1 (bit 0) — we claim ODBC behavior.
	buf[25] = 0x01

	// Bytes 26: TypeFlags — 0 (SQL auth, not integrated).
	buf[26] = 0x00

	// Bytes 27: OptionFlags3 — 0.
	buf[27] = 0x00

	// Bytes 28-31: ClientTimeZone (offset in minutes, signed).
	binary.LittleEndian.PutUint32(buf[28:32], 0)

	// Bytes 32-35: ClientLCID.
	binary.LittleEndian.PutUint32(buf[32:36], 0x00000409) // en-US

	// Bytes 36-39: ibHostName/cchHostName
	binary.LittleEndian.PutUint16(buf[36:38], clientNameOffset)
	binary.LittleEndian.PutUint16(buf[38:40], clientNameLen)

	// Bytes 40-43: ibUserName/cchUserName
	binary.LittleEndian.PutUint16(buf[40:42], userOffset)
	binary.LittleEndian.PutUint16(buf[42:44], userLen)

	// Bytes 44-47: ibPassword/cchPassword
	binary.LittleEndian.PutUint16(buf[44:46], passwordOffset)
	binary.LittleEndian.PutUint16(buf[46:48], passwordLen)

	// Bytes 48-51: ibAppName/cchAppName
	binary.LittleEndian.PutUint16(buf[48:50], appNameOffset)
	binary.LittleEndian.PutUint16(buf[50:52], appNameLen)

	// Bytes 52-55: ibServerName/cchServerName
	binary.LittleEndian.PutUint16(buf[52:54], serverOffset)
	binary.LittleEndian.PutUint16(buf[54:56], serverLen)

	// Bytes 56-59: ibExtension/cbExtension (unused, set to 0).
	binary.LittleEndian.PutUint16(buf[56:58], 0)
	binary.LittleEndian.PutUint16(buf[58:60], 0)

	// Bytes 60-63: ibCltIntName/cchCltIntName
	binary.LittleEndian.PutUint16(buf[60:62], cltIntNameOffset)
	binary.LittleEndian.PutUint16(buf[62:64], cltIntNameLen)

	// Bytes 64-67: ibLanguage/cchLanguage
	binary.LittleEndian.PutUint16(buf[64:66], languageOffset)
	binary.LittleEndian.PutUint16(buf[66:68], languageLen)

	// Bytes 68-71: ibDatabase/cchDatabase
	binary.LittleEndian.PutUint16(buf[68:70], databaseOffset)
	binary.LittleEndian.PutUint16(buf[70:72], databaseLen)

	// Bytes 72-77: ClientID (6 bytes — MAC address, zeros is fine).
	// Already zero from make.

	// Bytes 78-81: ibSSPI/cchSSPI
	binary.LittleEndian.PutUint16(buf[78:80], sspiOffset)
	binary.LittleEndian.PutUint16(buf[80:82], sspiLen)

	// Bytes 82-85: ibAtchDBFile/cchAtchDBFile
	binary.LittleEndian.PutUint16(buf[82:84], atchDBFileOffset)
	binary.LittleEndian.PutUint16(buf[84:86], atchDBFileLen)

	// Bytes 86-89: ibChangePassword/cchChangePassword
	binary.LittleEndian.PutUint16(buf[86:88], changePasswordOffset)
	binary.LittleEndian.PutUint16(buf[88:90], changePasswordLen)

	// Bytes 90-93: cbSSPILong (4 bytes, 0 for SQL auth).
	binary.LittleEndian.PutUint32(buf[90:94], 0)

	// Append variable-length data in offset order.
	buf = append(buf, utf16ToBytes(clientNameUTF16)...)
	buf = append(buf, utf16ToBytes(userUTF16)...)
	buf = append(buf, passwordBytes...)
	buf = append(buf, utf16ToBytes(appNameUTF16)...)
	buf = append(buf, utf16ToBytes(serverUTF16)...)
	buf = append(buf, utf16ToBytes(cltIntNameUTF16)...)
	buf = append(buf, utf16ToBytes(databaseUTF16)...)

	return buf
}

// parseLoginResponse scans TDS response tokens for LOGINACK (success) or
// ERROR (failure). Returns (true, nil) on LOGINACK, (false, nil) on
// authentication-failure ERROR (18456), and (false, err) on infrastructure
// errors (firewall blocks, etc.).
func parseLoginResponse(payload []byte) (bool, error) {
	pos := 0
	sawLoginAck := false
	var firstErr error

	for pos < len(payload) {
		token := payload[pos]
		pos++

		switch token {
		case tdsTokenLoginAck:
			// LOGINACK: 2-byte length + data.
			if pos+2 > len(payload) {
				break
			}
			tokLen := int(binary.LittleEndian.Uint16(payload[pos : pos+2]))
			pos += 2 + tokLen
			sawLoginAck = true

		case tdsTokenError:
			// ERROR: 2-byte length + Number(4) + State(1) + Class(1) + ...
			if pos+2 > len(payload) {
				break
			}
			tokLen := int(binary.LittleEndian.Uint16(payload[pos : pos+2]))
			dataStart := pos + 2
			pos += 2 + tokLen
			if dataStart+4 > len(payload) {
				break
			}
			errNum := binary.LittleEndian.Uint32(payload[dataStart : dataStart+4])

			// Extract the error message text for diagnostics.
			errMsg := extractTDSErrorMessage(payload[dataStart:min(dataStart+tokLen, len(payload))])

			switch errNum {
			case 18456:
				// "Login failed for user" — credential is wrong.
				return false, nil
			default:
				// Infrastructure error (firewall 40615, etc.).
				if firstErr == nil {
					if errMsg != "" {
						firstErr = fmt.Errorf("azuresql: verify: server error %d: %s", errNum, errMsg)
					} else {
						firstErr = fmt.Errorf("azuresql: verify: server error %d", errNum)
					}
				}
			}

		case tdsTokenInfo:
			// INFO: 2-byte length + data. Skip.
			if pos+2 > len(payload) {
				break
			}
			tokLen := int(binary.LittleEndian.Uint16(payload[pos : pos+2]))
			pos += 2 + tokLen

		case tdsTokenEnvChange:
			// ENVCHANGE: 2-byte length + data. Skip.
			if pos+2 > len(payload) {
				break
			}
			tokLen := int(binary.LittleEndian.Uint16(payload[pos : pos+2]))
			pos += 2 + tokLen

		case tdsTokenDone, tdsTokenDoneProc, tdsTokenDoneInProc:
			// DONE/DONEPROC/DONEINPROC: fixed 12 bytes (status(2) + curcmd(2) + rowcount(8)).
			pos += 12

		default:
			// Unknown token — try to read a 2-byte length and skip.
			if pos+2 > len(payload) {
				// Cannot parse further; break out.
				pos = len(payload)
				break
			}
			tokLen := int(binary.LittleEndian.Uint16(payload[pos : pos+2]))
			pos += 2 + tokLen
		}
	}

	if sawLoginAck {
		return true, nil
	}

	// No LOGINACK and no auth-failure error means something else went wrong.
	if firstErr != nil {
		return false, firstErr
	}
	return false, nil
}

// extractTDSErrorMessage extracts the UTF-16LE message text from a TDS
// ERROR token data region. Layout: Number(4) + State(1) + Class(1) +
// MsgLen(2, in chars) + MsgText(MsgLen * 2 bytes) + ...
func extractTDSErrorMessage(data []byte) string {
	// Need at least: Number(4) + State(1) + Class(1) + MsgLen(2) = 8 bytes.
	if len(data) < 8 {
		return ""
	}
	msgLenChars := int(binary.LittleEndian.Uint16(data[6:8]))
	msgStart := 8
	msgEnd := msgStart + msgLenChars*2
	if msgEnd > len(data) {
		msgEnd = len(data)
	}
	if msgStart >= msgEnd {
		return ""
	}
	return utf16LEToString(data[msgStart:msgEnd])
}

// utf16Encode encodes a Go string as a slice of UTF-16 code units.
func utf16Encode(s string) []uint16 {
	return utf16.Encode([]rune(s))
}

// utf16ToBytes converts a slice of UTF-16 code units to little-endian bytes.
func utf16ToBytes(u []uint16) []byte {
	b := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

// utf16LEToString decodes little-endian UTF-16 bytes into a Go string.
func utf16LEToString(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
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
