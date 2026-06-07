package azuresqlconn

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestFromData_Positive(t *testing.T) {
	conn := "Server=tcp:my-srv.database.windows.net,1433;Initial Catalog=appdb;Persist Security Info=False;User ID=admin;Password=Sup3rSecret!;MultipleActiveResultSets=False;"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(conn))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "Sup3rSecret!" {
		t.Fatalf("password: %q", res[0].Raw)
	}
	if got := res[0].ExtraData["server"]; got != "my-srv.database.windows.net" {
		t.Fatalf("server: %q", got)
	}
	if got := res[0].ExtraData["user_id"]; got != "admin" {
		t.Fatalf("user: %q", got)
	}
	if got := res[0].ExtraData["database"]; got != "appdb" {
		t.Fatalf("database: %q", got)
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("severity: %v", res[0].Severity)
	}
}

func TestFromData_NoHost(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("Server=tcp:localhost;User ID=u;Password=p;"))
	if len(res) != 0 {
		t.Fatalf("expected 0")
	}
}

func TestFromData_NoPassword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("Server=tcp:srv.database.windows.net,1433;User ID=u;Authentication=Active Directory Default;"))
	if len(res) != 0 {
		t.Fatalf("expected 0")
	}
}

// TestFromData_SuppressFP asserts that template/placeholder and
// interpolation passwords are no longer emitted as Critical secrets after
// the semantic hardening.
func TestFromData_SuppressFP(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{
			name: "documentation placeholder your_password_here",
			in:   "Server=tcp:demo.database.windows.net,1433;Initial Catalog=appdb;User ID=admin;Password=your_password_here;",
		},
		{
			name: "CI env-var interpolation",
			in:   "Server=tcp:srv.database.windows.net,1433;User ID=app;Password=$(DB_PASSWORD);",
		},
		{
			name: "brace template token",
			in:   "Server=tcp:srv.database.windows.net,1433;User ID=app;Password={password};",
		},
		{
			name: "low-entropy dictionary placeholder",
			in:   "Server=tcp:srv.database.windows.net,1433;User ID=app;Password=changeme;",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, _ := Scanner{}.FromData(context.Background(), false, []byte(tc.in))
			if len(res) != 0 {
				t.Fatalf("expected 0 results, got %d (raw=%q)", len(res), res[0].Raw)
			}
		})
	}
}

// TestFromData_NoCrossStringPairing asserts the tightened vicinity window
// does not pair a host from a passwordless/AAD connection string with a
// Password belonging to an adjacent concatenated connection string many
// segments away.
func TestFromData_NoCrossStringPairing(t *testing.T) {
	// First conn: host present, AAD auth, no password — separated from the
	// second conn's Password by more than the {0,3} vicinity window.
	in := "Server=tcp:aad.database.windows.net,1433;Initial Catalog=db1;Authentication=Active Directory Default;Encrypt=True;TrustServerCertificate=False;Persist Security Info=False;Connection Timeout=30;Pooling=True;Password=RealOtherDbPass;"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(in))
	if len(res) != 0 {
		t.Fatalf("expected 0 cross-string pairings, got %d (raw=%q, rawv2=%q)", len(res), res[0].Raw, res[0].RawV2)
	}
}

// TestFromData_StillDetectsReal asserts a genuine high-entropy password
// inside the vicinity window is still detected after hardening.
func TestFromData_StillDetectsReal(t *testing.T) {
	conn := "Server=tcp:prod.database.windows.net,1433;Initial Catalog=appdb;User ID=admin;Password=x9K#mQ7vL2pR;"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(conn))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "x9K#mQ7vL2pR" {
		t.Fatalf("password: %q", res[0].Raw)
	}
	if got := res[0].ExtraData["server"]; got != "prod.database.windows.net" {
		t.Fatalf("server: %q", got)
	}
}

// TestFromData_DataSourceKeyword asserts the alternate host-bearing keyword
// (Data Source) is still anchored and detected.
func TestFromData_DataSourceKeyword(t *testing.T) {
	conn := "Data Source=alt.database.windows.net,1433;Initial Catalog=db;User ID=u;Password=Tr0ub4dor&3X;"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(conn))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

// --- Connection string parsing tests ---

func TestConnStringFields_Full(t *testing.T) {
	conn := "Server=tcp:my-srv.database.windows.net,1433;Initial Catalog=appdb;User ID=admin;Password=Sup3rSecret!"
	server, port, user, password, database := connStringFields(conn)

	if server != "my-srv.database.windows.net" {
		t.Fatalf("server: %q", server)
	}
	if port != "1433" {
		t.Fatalf("port: %q", port)
	}
	if user != "admin" {
		t.Fatalf("user: %q", user)
	}
	if password != "Sup3rSecret!" {
		t.Fatalf("password: %q", password)
	}
	if database != "appdb" {
		t.Fatalf("database: %q", database)
	}
}

func TestConnStringFields_NoTCPPrefix(t *testing.T) {
	conn := "Server=my-db.database.windows.net;User ID=sa;Password=P@ssw0rd"
	server, port, user, password, _ := connStringFields(conn)

	if server != "my-db.database.windows.net" {
		t.Fatalf("server: %q", server)
	}
	if port != "1433" {
		t.Fatalf("port: expected default 1433, got %q", port)
	}
	if user != "sa" {
		t.Fatalf("user: %q", user)
	}
	if password != "P@ssw0rd" {
		t.Fatalf("password: %q", password)
	}
}

func TestConnStringFields_CustomPort(t *testing.T) {
	conn := "Server=tcp:my-db.database.windows.net,3342;User ID=u;Password=p"
	_, port, _, _, _ := connStringFields(conn)
	if port != "3342" {
		t.Fatalf("port: expected 3342, got %q", port)
	}
}

func TestConnStringFields_DatabaseKeyword(t *testing.T) {
	conn := "Server=tcp:x.database.windows.net;Database=mydb;User ID=u;Password=p"
	_, _, _, _, database := connStringFields(conn)
	if database != "mydb" {
		t.Fatalf("database: %q", database)
	}
}

func TestConnStringFields_EmptyServer(t *testing.T) {
	conn := "User ID=admin;Password=secret"
	server, _, _, _, _ := connStringFields(conn)
	if server != "" {
		t.Fatalf("expected empty server, got %q", server)
	}
}

// --- UTF-16 encoding tests ---

func TestUTF16Encode(t *testing.T) {
	encoded := utf16Encode("abc")
	if len(encoded) != 3 {
		t.Fatalf("expected 3 code units, got %d", len(encoded))
	}
	if encoded[0] != 'a' || encoded[1] != 'b' || encoded[2] != 'c' {
		t.Fatalf("unexpected encoding: %v", encoded)
	}
}

func TestUTF16ToBytes(t *testing.T) {
	encoded := utf16Encode("AB")
	b := utf16ToBytes(encoded)
	if len(b) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(b))
	}
	// 'A' = 0x0041 in UTF-16LE => [0x41, 0x00]
	if b[0] != 0x41 || b[1] != 0x00 {
		t.Fatalf("unexpected bytes for 'A': %x %x", b[0], b[1])
	}
}

func TestUTF16LEToString(t *testing.T) {
	// "Hi" in UTF-16LE
	b := []byte{0x48, 0x00, 0x69, 0x00}
	s := utf16LEToString(b)
	if s != "Hi" {
		t.Fatalf("expected 'Hi', got %q", s)
	}
}

func TestUTF16LEToString_OddLength(t *testing.T) {
	// Odd byte count — last byte truncated.
	b := []byte{0x48, 0x00, 0x69}
	s := utf16LEToString(b)
	if s != "H" {
		t.Fatalf("expected 'H' (truncated), got %q", s)
	}
}

// --- LOGIN7 packet construction tests ---

func TestBuildLogin7_MinimalValid(t *testing.T) {
	payload := buildLogin7("test.database.windows.net", "user", "pass", "db")

	// The fixed header is 94 bytes; total must be at least that.
	if len(payload) < 94 {
		t.Fatalf("LOGIN7 payload too short: %d bytes", len(payload))
	}

	// Bytes 0-3: total length must match actual payload length.
	totalLen := binary.LittleEndian.Uint32(payload[0:4])
	if int(totalLen) != len(payload) {
		t.Fatalf("LOGIN7 length field %d != actual %d", totalLen, len(payload))
	}

	// Bytes 4-7: TDS version should be 7.4 (0x74000004).
	tdsVer := binary.LittleEndian.Uint32(payload[4:8])
	if tdsVer != 0x74000004 {
		t.Fatalf("TDS version: 0x%08x, expected 0x74000004", tdsVer)
	}
}

func TestBuildLogin7_PasswordObfuscation(t *testing.T) {
	// The password "A" (UTF-16LE = [0x41, 0x00]) should be obfuscated.
	// For byte 0x41: swap nibbles -> 0x14, XOR 0xA5 -> 0xB1
	// For byte 0x00: swap nibbles -> 0x00, XOR 0xA5 -> 0xA5
	payload := buildLogin7("s.database.windows.net", "u", "A", "")

	// Find the password in the payload: offset at bytes 44-45, length at 46-47.
	pwOffset := binary.LittleEndian.Uint16(payload[44:46])
	pwLen := binary.LittleEndian.Uint16(payload[46:48])

	if pwLen != 1 {
		t.Fatalf("password length: %d chars, expected 1", pwLen)
	}

	// Password occupies pwLen * 2 bytes starting at pwOffset.
	pwBytes := payload[pwOffset : pwOffset+pwLen*2]

	expectedByte0 := byte((((0x41 << 4) & 0xF0) | ((0x41 >> 4) & 0x0F)) ^ 0xA5)
	expectedByte1 := byte((((0x00 << 4) & 0xF0) | ((0x00 >> 4) & 0x0F)) ^ 0xA5)

	if pwBytes[0] != expectedByte0 || pwBytes[1] != expectedByte1 {
		t.Fatalf("password obfuscation: got [%02x, %02x], expected [%02x, %02x]",
			pwBytes[0], pwBytes[1], expectedByte0, expectedByte1)
	}
}

func TestBuildLogin7_FieldOffsets(t *testing.T) {
	// Verify that all variable-length fields are properly offset.
	payload := buildLogin7("srv.database.windows.net", "admin", "Pass!23", "mydb")

	totalLen := binary.LittleEndian.Uint32(payload[0:4])
	if int(totalLen) != len(payload) {
		t.Fatalf("total length mismatch: header says %d, actual %d", totalLen, len(payload))
	}

	// Verify username can be read back from the payload.
	userOffset := binary.LittleEndian.Uint16(payload[40:42])
	userLen := binary.LittleEndian.Uint16(payload[42:44])
	if userLen == 0 {
		t.Fatal("username length is 0")
	}
	userBytes := payload[userOffset : userOffset+userLen*2]
	userName := utf16LEToString(userBytes)
	if userName != "admin" {
		t.Fatalf("username roundtrip: %q", userName)
	}

	// Verify server name can be read back.
	serverOffset := binary.LittleEndian.Uint16(payload[52:54])
	serverLen := binary.LittleEndian.Uint16(payload[54:56])
	if serverLen == 0 {
		t.Fatal("server length is 0")
	}
	serverBytes := payload[serverOffset : serverOffset+serverLen*2]
	serverName := utf16LEToString(serverBytes)
	if serverName != "srv.database.windows.net" {
		t.Fatalf("server roundtrip: %q", serverName)
	}

	// Verify database can be read back.
	dbOffset := binary.LittleEndian.Uint16(payload[68:70])
	dbLen := binary.LittleEndian.Uint16(payload[70:72])
	if dbLen == 0 {
		t.Fatal("database length is 0")
	}
	dbBytes := payload[dbOffset : dbOffset+dbLen*2]
	dbName := utf16LEToString(dbBytes)
	if dbName != "mydb" {
		t.Fatalf("database roundtrip: %q", dbName)
	}
}

// --- PRELOGIN packet tests ---

func TestBuildPreloginPacket(t *testing.T) {
	pkt := buildPreloginPacket()

	// Must start with TDS header: type=0x12 (PRELOGIN), status=0x01 (EOM).
	if len(pkt) < 8 {
		t.Fatalf("PRELOGIN packet too short: %d bytes", len(pkt))
	}
	if pkt[0] != tdsPacketTypePreLogin {
		t.Fatalf("packet type: 0x%02x, expected 0x%02x", pkt[0], tdsPacketTypePreLogin)
	}
	if pkt[1] != tdsStatusEOM {
		t.Fatalf("packet status: 0x%02x, expected 0x%02x", pkt[1], tdsStatusEOM)
	}

	// Length field must match actual packet length.
	pktLen := binary.BigEndian.Uint16(pkt[2:4])
	if int(pktLen) != len(pkt) {
		t.Fatalf("packet length field %d != actual %d", pktLen, len(pkt))
	}

	// Payload must contain the TERMINATOR byte (0xFF).
	payload := pkt[8:]
	foundTerminator := false
	for _, b := range payload {
		if b == preloginTerminator {
			foundTerminator = true
			break
		}
	}
	if !foundTerminator {
		t.Fatal("PRELOGIN payload missing TERMINATOR (0xFF)")
	}
}

// --- Login response parsing tests ---

func TestParseLoginResponse_LoginAck(t *testing.T) {
	// Build a minimal LOGINACK token: 0xAD + length(2) + dummy data.
	payload := []byte{tdsTokenLoginAck}
	payload = appendUint16LE(payload, 10) // length = 10
	payload = append(payload, make([]byte, 10)...)

	// DONE token to terminate.
	payload = append(payload, tdsTokenDone)
	payload = append(payload, make([]byte, 12)...)

	verified, err := parseLoginResponse(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Fatal("expected verified=true for LOGINACK")
	}
}

func TestParseLoginResponse_AuthFailure(t *testing.T) {
	// Build an ERROR token with error number 18456 (Login failed).
	payload := []byte{tdsTokenError}

	// ERROR data: Number(4) + State(1) + Class(1) + MsgLen(2) + Msg +
	// ServerNameLen(2) + ProcNameLen(2) + LineNumber(4)
	var errData []byte
	errData = appendUint32LE(errData, 18456) // Number
	errData = append(errData, 1)              // State
	errData = append(errData, 14)             // Class
	errData = appendUint16LE(errData, 0)      // MsgLen = 0
	errData = appendUint16LE(errData, 0)      // ServerNameLen = 0
	errData = appendUint16LE(errData, 0)      // ProcNameLen = 0
	errData = appendUint32LE(errData, 0)      // LineNumber

	payload = appendUint16LE(payload, uint16(len(errData)))
	payload = append(payload, errData...)

	// DONE token.
	payload = append(payload, tdsTokenDone)
	payload = append(payload, make([]byte, 12)...)

	verified, err := parseLoginResponse(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false for error 18456")
	}
}

func TestParseLoginResponse_FirewallError(t *testing.T) {
	// Build an ERROR token with error number 40615 (firewall).
	payload := []byte{tdsTokenError}

	var errData []byte
	errData = appendUint32LE(errData, 40615) // Number
	errData = append(errData, 1)              // State
	errData = append(errData, 14)             // Class
	errData = appendUint16LE(errData, 0)      // MsgLen = 0
	errData = appendUint16LE(errData, 0)      // ServerNameLen
	errData = appendUint16LE(errData, 0)      // ProcNameLen
	errData = appendUint32LE(errData, 0)      // LineNumber

	payload = appendUint16LE(payload, uint16(len(errData)))
	payload = append(payload, errData...)

	// DONE token.
	payload = append(payload, tdsTokenDone)
	payload = append(payload, make([]byte, 12)...)

	verified, err := parseLoginResponse(payload)
	if verified {
		t.Fatal("expected verified=false for firewall error")
	}
	if err == nil {
		t.Fatal("expected non-nil error for firewall block")
	}
	if !strings.Contains(err.Error(), "40615") {
		t.Fatalf("error should mention error number 40615: %v", err)
	}
}

func TestParseLoginResponse_EmptyPayload(t *testing.T) {
	verified, err := parseLoginResponse(nil)
	if verified {
		t.Fatal("expected verified=false for empty payload")
	}
	if err != nil {
		t.Fatalf("expected nil error for empty payload, got: %v", err)
	}
}

func TestParseLoginResponse_LoginAckWithEnvChange(t *testing.T) {
	// Realistic response: ENVCHANGE + INFO + LOGINACK + DONE.
	var payload []byte

	// ENVCHANGE token with some data.
	payload = append(payload, tdsTokenEnvChange)
	payload = appendUint16LE(payload, 6)
	payload = append(payload, make([]byte, 6)...)

	// INFO token.
	payload = append(payload, tdsTokenInfo)
	payload = appendUint16LE(payload, 8)
	payload = append(payload, make([]byte, 8)...)

	// LOGINACK token.
	payload = append(payload, tdsTokenLoginAck)
	payload = appendUint16LE(payload, 10)
	payload = append(payload, make([]byte, 10)...)

	// DONE token.
	payload = append(payload, tdsTokenDone)
	payload = append(payload, make([]byte, 12)...)

	verified, err := parseLoginResponse(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !verified {
		t.Fatal("expected verified=true for LOGINACK in mixed-token stream")
	}
}

func TestParseLoginResponse_ErrorWithMessage(t *testing.T) {
	// Build ERROR token with error number 40615 and a UTF-16LE message.
	payload := []byte{tdsTokenError}

	msg := utf16Encode("Firewall blocked")
	msgBytes := utf16ToBytes(msg)

	var errData []byte
	errData = appendUint32LE(errData, 40615)             // Number
	errData = append(errData, 1)                          // State
	errData = append(errData, 14)                         // Class
	errData = appendUint16LE(errData, uint16(len(msg)))   // MsgLen in chars
	errData = append(errData, msgBytes...)                 // MsgText
	errData = appendUint16LE(errData, 0)                  // ServerNameLen
	errData = appendUint16LE(errData, 0)                  // ProcNameLen
	errData = appendUint32LE(errData, 0)                  // LineNumber

	payload = appendUint16LE(payload, uint16(len(errData)))
	payload = append(payload, errData...)

	// DONE token.
	payload = append(payload, tdsTokenDone)
	payload = append(payload, make([]byte, 12)...)

	_, err := parseLoginResponse(payload)
	if err == nil {
		t.Fatal("expected error for firewall block")
	}
	if !strings.Contains(err.Error(), "Firewall blocked") {
		t.Fatalf("error should contain message text: %v", err)
	}
}

// --- Verify integration tests (network) ---

func TestVerify_MissingServer(t *testing.T) {
	_, err := Scanner{}.Verify(context.Background(), "User ID=admin;Password=secret")
	if err == nil {
		t.Fatal("expected error for missing server")
	}
}

func TestVerify_MissingUser(t *testing.T) {
	_, err := Scanner{}.Verify(context.Background(), "Server=tcp:x.database.windows.net;Password=secret")
	if err == nil {
		t.Fatal("expected error for missing user")
	}
}

func TestVerify_MissingPassword(t *testing.T) {
	_, err := Scanner{}.Verify(context.Background(), "Server=tcp:x.database.windows.net;User ID=admin")
	if err == nil {
		t.Fatal("expected error for missing password")
	}
}

func TestVerify_UnreachableHost(t *testing.T) {
	// Use a non-existent subdomain that matches *.database.windows.net.
	conn := "Server=tcp:nonexistent-test-12345.database.windows.net,1433;User ID=admin;Password=Sup3rSecret!"
	verified, err := Scanner{}.Verify(context.Background(), conn)
	if verified {
		t.Fatal("expected verified=false for unreachable host")
	}
	// err may be a DNS or dial error — either is acceptable.
	_ = err
}

// --- TDS packet helpers tests ---

func TestWrapTDSPacket(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	pkt := wrapTDSPacket(tdsPacketTypeLogin7, payload)

	if pkt[0] != tdsPacketTypeLogin7 {
		t.Fatalf("packet type: 0x%02x", pkt[0])
	}
	if pkt[1] != tdsStatusEOM {
		t.Fatalf("status: 0x%02x", pkt[1])
	}

	pktLen := binary.BigEndian.Uint16(pkt[2:4])
	if pktLen != 11 { // 8 header + 3 payload
		t.Fatalf("packet length: %d, expected 11", pktLen)
	}

	if pkt[8] != 0x01 || pkt[9] != 0x02 || pkt[10] != 0x03 {
		t.Fatal("payload bytes mismatch")
	}
}

// --- Compile-time interface checks ---

func TestInterfaceCompliance(t *testing.T) {
	var _ detectors.Detector = Scanner{}
	var _ detectors.Verifier = Scanner{}
}

// appendUint16LE appends a uint16 in little-endian byte order to buf.
func appendUint16LE(buf []byte, v uint16) []byte {
	return append(buf, byte(v), byte(v>>8))
}

// appendUint32LE appends a uint32 in little-endian byte order to buf.
func appendUint32LE(buf []byte, v uint32) []byte {
	return append(buf, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}
