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
