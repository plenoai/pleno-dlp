package mongodb

import (
	"context"
	"encoding/binary"
	"testing"
)

func TestFromData_StandardScheme(t *testing.T) {
	body := "MONGO_URL=mongodb://app:p4ss@db.example.com:27017/app"
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "p4ss" {
		t.Fatalf("password mismatch: %q", res[0].Raw)
	}
	if got := res[0].ExtraData["host"]; got != "db.example.com:27017" {
		t.Fatalf("host: %q", got)
	}
	if res[0].ExtraData["srv"] == "true" {
		t.Fatal("srv flag should be false for standard scheme")
	}
}

func TestFromData_SrvScheme(t *testing.T) {
	body := "mongodb+srv://app:hunter2@cluster.mongodb.net/app?retryWrites=true"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1")
	}
	if string(res[0].Raw) != "hunter2" {
		t.Fatalf("password: %q", res[0].Raw)
	}
	if got := res[0].ExtraData["srv"]; got != "true" {
		t.Fatalf("srv flag: %q", got)
	}
	if got := res[0].ExtraData["host"]; got != "cluster.mongodb.net" {
		t.Fatalf("host: %q", got)
	}
}

func TestFromData_NoUserinfo(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("mongodb://db.local:27017"))
	if len(res) != 0 {
		t.Fatalf("expected 0")
	}
}

// TestFromData_SuppressesPlaceholders asserts that syntactically-perfect
// URIs carrying documentation/template/quickstart passwords are dropped.
// Without the denylist/entropy gate these would all match at SeverityHigh.
func TestFromData_SuppressesPlaceholders(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"denylist_password", "mongodb://admin:password@db.example.com:27017/app"},
		{"denylist_changeme", "mongodb+srv://user:changeme@cluster.mongodb.net/db"},
		{"denylist_case_insensitive", "mongodb://root:PASSWORD@prod-cluster.internal:27017/app"},
		{"compose_localhost", "mongodb://root:secret@localhost:27017/admin"},
		{"compose_mongo_service", "mongodb://admin:password@mongo:27017"},
		{"low_entropy_repetition", "mongodb://app:aaaa@real-prod-host.net:27017/app"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Scanner{}.FromData(context.Background(), false, []byte(tc.body))
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if len(res) != 0 {
				t.Fatalf("expected 0 results (placeholder suppressed), got %d: %q", len(res), res[0].Raw)
			}
		})
	}
}

// TestFromData_RealPasswordStillDetected guards against over-suppression:
// a legitimate-looking credential at the same host shape that a compose
// snippet would use must still be reported.
func TestFromData_RealPasswordStillDetected(t *testing.T) {
	body := "mongodb://svc:Xk9$mZ2pQ7wL@localhost:27017/orders"
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 (real cred retained), got %d", len(res))
	}
	if string(res[0].Raw) != "Xk9$mZ2pQ7wL" {
		t.Fatalf("password mismatch: %q", res[0].Raw)
	}
}

// --- URI parsing tests for Verify ---

func TestManualHostUser(t *testing.T) {
	cases := []struct {
		name     string
		uri      string
		wantHost string
		wantUser string
	}{
		{
			name:     "standard with port",
			uri:      "mongodb://app:secret@db.example.com:27017/mydb",
			wantHost: "db.example.com:27017",
			wantUser: "app",
		},
		{
			name:     "standard no port",
			uri:      "mongodb://user:pass@db.example.com/mydb",
			wantHost: "db.example.com",
			wantUser: "user",
		},
		{
			name:     "srv scheme",
			uri:      "mongodb+srv://admin:s3cr3t@cluster.mongodb.net/db",
			wantHost: "cluster.mongodb.net",
			wantUser: "admin",
		},
		{
			name:     "with query params",
			uri:      "mongodb://u:p@host:27017/db?retryWrites=true",
			wantHost: "host:27017",
			wantUser: "u",
		},
		{
			name:     "no scheme",
			uri:      "not-a-uri",
			wantHost: "",
			wantUser: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, user := manualHostUser(tc.uri)
			if host != tc.wantHost {
				t.Errorf("host: got %q, want %q", host, tc.wantHost)
			}
			if user != tc.wantUser {
				t.Errorf("user: got %q, want %q", user, tc.wantUser)
			}
		})
	}
}

func TestShouldSkipHost(t *testing.T) {
	for _, h := range []string{"localhost", "127.0.0.1", "::1", "example.com", "host.example.com"} {
		if !shouldSkipHost(h) {
			t.Errorf("shouldSkipHost(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"db.prod.internal", "cluster.mongodb.net", "10.0.0.1"} {
		if shouldSkipHost(h) {
			t.Errorf("shouldSkipHost(%q) = true, want false", h)
		}
	}
}

func TestVerify_InvalidURI(t *testing.T) {
	_, err := Scanner{}.Verify(context.Background(), "://bad\x7furi")
	if err == nil {
		t.Fatal("expected error for invalid URI, got nil")
	}
}

func TestVerify_SkipsLocalhost(t *testing.T) {
	// Verify against localhost should return (false, nil) without dialing.
	verified, err := Scanner{}.Verify(context.Background(), "mongodb://user:pass@localhost:27017/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false for localhost")
	}
}

func TestVerify_SkipsExampleHost(t *testing.T) {
	verified, err := Scanner{}.Verify(context.Background(), "mongodb://user:pass@example.com:27017/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false for example.com")
	}
}

func TestVerify_UnreachableHost(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1, routed to nowhere.
	verified, err := Scanner{}.Verify(context.Background(), "mongodb://user:pass@192.0.2.1:27017/db")
	if verified {
		t.Fatal("expected verified=false for unreachable host")
	}
	if err == nil {
		t.Fatal("expected a dial error for unreachable host, got nil")
	}
}

func TestVerify_DefaultPort(t *testing.T) {
	// Confirm that a URI without an explicit port uses 27017 and does not panic.
	verified, err := Scanner{}.Verify(context.Background(), "mongodb://user:pass@192.0.2.1/db")
	if verified {
		t.Fatal("expected verified=false for unreachable host")
	}
	if err == nil {
		t.Fatal("expected a dial error for unreachable host")
	}
}

func TestFromData_SrvVerifySkipped(t *testing.T) {
	body := "mongodb+srv://app:hunter2@cluster.mongodb.net/db"
	res, err := Scanner{}.FromData(context.Background(), true, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("SRV URIs should not be verified")
	}
	if got := res[0].ExtraData["srv_requires_driver"]; got != "true" {
		t.Fatalf("expected srv_requires_driver=true, got %q", got)
	}
}

func TestBuildIsMasterMsg(t *testing.T) {
	msg := buildIsMasterMsg()
	// Verify the wire protocol header.
	if len(msg) < 16 {
		t.Fatalf("message too short: %d bytes", len(msg))
	}
	totalLen := binary.LittleEndian.Uint32(msg[0:4])
	if int(totalLen) != len(msg) {
		t.Fatalf("messageLength mismatch: header says %d, actual %d", totalLen, len(msg))
	}
	opCode := binary.LittleEndian.Uint32(msg[12:16])
	if opCode != 2013 {
		t.Fatalf("opCode: got %d, want 2013 (OP_MSG)", opCode)
	}
}
