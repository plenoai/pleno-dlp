package bitbucketserver

import (
	"context"
	"strings"
	"testing"
)

const dummyHTTPAccess = "BBDC-OTQyNzgwNTk0NjI4OnUlfBFxe9SrJqZbnY7zxMbW1ZmgWQ5q"
const dummyPAT = "0123456789abcdefghijklmnopqrstuvwxyzABCD"

func TestFromData_HTTPAccess(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("STASH_TOKEN="+dummyHTTPAccess))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyHTTPAccess {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if res[0].Verified {
		t.Fatal("BitbucketServer is unverified-by-design (host unknown); got Verified=true")
	}
}

func TestFromData_PATWithKeyword(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("# bitbucket pat\nTOKEN="+dummyPAT))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyPAT {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_PATNoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("nonce="+dummyPAT))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyHTTPAccess)
	if r == dummyHTTPAccess {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "BBDC-OTQ") {
		t.Fatalf("missing prefix: %q", r)
	}
}
