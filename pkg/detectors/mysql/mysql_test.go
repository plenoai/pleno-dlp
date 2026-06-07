package mysql

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"testing"
)

func TestFromData_Positive(t *testing.T) {
	body := "DATABASE_URL=mysql://root:rootp4ss@db.example.com:3306/app"
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "rootp4ss" {
		t.Fatalf("password mismatch: %q", res[0].Raw)
	}
}

func TestFromData_MysqlX(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("mysqlx://u:p@h:33060"))
	if len(res) != 1 {
		t.Fatalf("expected 1")
	}
}

func TestFromData_NoUserinfo(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("mysql://db.local:3306/app"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

// --- URI parsing tests for Verify ---

func TestShouldSkipHost(t *testing.T) {
	for _, h := range []string{"localhost", "127.0.0.1", "::1", "example.com", "host.example.com"} {
		if !shouldSkipHost(h) {
			t.Errorf("shouldSkipHost(%q) = false, want true", h)
		}
	}
	for _, h := range []string{"db.prod.internal", "mysql.example.org", "10.0.0.1"} {
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
	verified, err := Scanner{}.Verify(context.Background(), "mysql://root:pass@localhost:3306/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false for localhost")
	}
}

func TestVerify_SkipsExampleHost(t *testing.T) {
	verified, err := Scanner{}.Verify(context.Background(), "mysql://root:pass@example.com/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verified {
		t.Fatal("expected verified=false for example.com")
	}
}

func TestVerify_UnreachableHost(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1, routed to nowhere.
	verified, err := Scanner{}.Verify(context.Background(), "mysql://root:pass@192.0.2.1:3306/db")
	if verified {
		t.Fatal("expected verified=false for unreachable host")
	}
	if err == nil {
		t.Fatal("expected a dial error for unreachable host, got nil")
	}
}

func TestVerify_DefaultPort(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{"mysql default 3306", "mysql://root:pass@192.0.2.1/db"},
		{"mysqlx default 33060", "mysqlx://root:pass@192.0.2.1/db"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verified, err := Scanner{}.Verify(context.Background(), tc.uri)
			if verified {
				t.Fatal("expected verified=false for unreachable host")
			}
			if err == nil {
				t.Fatal("expected a dial error for unreachable host")
			}
		})
	}
}

// TestNativePasswordAuth verifies the SHA1-based auth hash computation.
func TestNativePasswordAuth(t *testing.T) {
	password := "testpassword"
	salt := make([]byte, 20)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	result := nativePasswordAuth(password, salt)
	if len(result) != sha1.Size {
		t.Fatalf("expected %d bytes, got %d", sha1.Size, len(result))
	}

	// Verify determinism: same inputs produce same output.
	result2 := nativePasswordAuth(password, salt)
	for i := range result {
		if result[i] != result2[i] {
			t.Fatalf("non-deterministic at byte %d", i)
		}
	}
}

// TestNativePasswordAuth_Empty verifies empty password returns nil.
func TestNativePasswordAuth_Empty(t *testing.T) {
	result := nativePasswordAuth("", []byte{1, 2, 3})
	if result != nil {
		t.Fatalf("expected nil for empty password, got %v", result)
	}
}

// TestBuildHandshakeResponse verifies the packet is well-formed.
func TestBuildHandshakeResponse(t *testing.T) {
	auth := nativePasswordAuth("secret", make([]byte, 20))
	resp := buildHandshakeResponse("root", auth, "mydb")

	// Minimum size: 4 (caps) + 4 (maxpkt) + 1 (charset) + 23 (reserved) +
	// 5 (root\0) + 1 (auth_len) + 20 (auth) + 5 (mydb\0) + 21 (plugin\0)
	if len(resp) < 84 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}

	// Check capability flags include CLIENT_CONNECT_WITH_DB.
	capFlags := binary.LittleEndian.Uint32(resp[0:4])
	if capFlags&0x00000008 == 0 {
		t.Fatal("CLIENT_CONNECT_WITH_DB flag not set")
	}
}

// TestBuildHandshakeResponse_NoDB verifies the packet without a database.
func TestBuildHandshakeResponse_NoDB(t *testing.T) {
	resp := buildHandshakeResponse("user", nil, "")

	capFlags := binary.LittleEndian.Uint32(resp[0:4])
	if capFlags&0x00000008 != 0 {
		t.Fatal("CLIENT_CONNECT_WITH_DB flag should not be set without database")
	}
}
