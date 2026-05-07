package kafka

import (
	"context"
	"strings"
	"testing"
)

func TestFromData_PropertyStyle(t *testing.T) {
	body := strings.Join([]string{
		"bootstrap.servers=kafka.example.com:9093",
		"sasl.username=alice",
		"sasl.password=hunter2",
	}, "\n")
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "hunter2" {
		t.Fatalf("password: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != "alice" {
		t.Fatalf("username: %q", res[0].RawV2)
	}
	if got := res[0].ExtraData["bootstrap_servers"]; got != "kafka.example.com:9093" {
		t.Fatalf("bootstrap: %q", got)
	}
}

func TestFromData_JAASStyle(t *testing.T) {
	body := `sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="bob" password="s3cr3t";`
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "s3cr3t" {
		t.Fatalf("password: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != "bob" {
		t.Fatalf("username: %q", res[0].RawV2)
	}
}

func TestFromData_NoCredentials(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("bootstrap.servers=kafka:9092"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}
