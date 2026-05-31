package mongodb

import (
	"context"
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
