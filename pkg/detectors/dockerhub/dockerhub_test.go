package dockerhub

import (
	"context"
	"testing"
)

const dummy = "dckr_pat_AbCdEfGhIjKlMnOpQrStUvWx12"

func TestFromData_Positive(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("DOCKERHUB_TOKEN="+dummy))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw: %q", res[0].Raw)
	}
}

func TestFromData_WithUsername(t *testing.T) {
	body := "DOCKER_USERNAME=alice\nDOCKERHUB_TOKEN=" + dummy
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1")
	}
	if string(res[0].RawV2) != "alice" {
		t.Fatalf("rawv2: %q", res[0].RawV2)
	}
	if got := res[0].ExtraData["username"]; got != "alice" {
		t.Fatalf("username: %q", got)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("password=hunter2"))
	if len(res) != 0 {
		t.Fatalf("expected 0")
	}
}
