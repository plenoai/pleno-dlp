//go:build detector_unit

package rabbitmq

import (
	"context"
	"testing"
)

func TestFromData_AMQP(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("amqp://guest:secret@rabbit:5672/vhost"))
	if len(res) != 1 {
		t.Fatalf("expected 1")
	}
	if string(res[0].Raw) != "secret" {
		t.Fatalf("password: %q", res[0].Raw)
	}
	if got := res[0].ExtraData["host"]; got != "rabbit:5672" {
		t.Fatalf("host: %q", got)
	}
}

func TestFromData_AMQPS(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("amqps://app:s3cr3t@mq.example.com:5671"))
	if len(res) != 1 {
		t.Fatalf("expected 1")
	}
}

func TestFromData_NoUserinfo(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("amqp://broker:5672"))
	if len(res) != 0 {
		t.Fatalf("expected 0")
	}
}
