package privatekey

import (
	"context"
	"strings"
	"testing"
)

const rsaBlock = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
-----END RSA PRIVATE KEY-----`

const opensshBlock = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACBzZXJ2ZXIuYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==
-----END OPENSSH PRIVATE KEY-----`

const pkcs8Block = `-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKj3xMwwxxxxxxxx
-----END PRIVATE KEY-----`

func TestFromData_RSA(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("preamble\n"+rsaBlock+"\nepilogue"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].ExtraData["algorithm"] != "RSA" {
		t.Fatalf("algorithm wrong: %+v", res[0].ExtraData)
	}
}

func TestFromData_OpenSSH(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(opensshBlock))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].ExtraData["algorithm"] != "OPENSSH" {
		t.Fatalf("algorithm wrong: %+v", res[0].ExtraData)
	}
}

func TestFromData_PKCS8(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(pkcs8Block))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].ExtraData["algorithm"] != "PKCS8" {
		t.Fatalf("algorithm wrong: %+v", res[0].ExtraData)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("PRIVATE KEY but no markers"))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(rsaBlock))
	if !strings.Contains(res[0].Redacted, "BEGIN RSA PRIVATE KEY") {
		t.Fatalf("redacted missing alg: %q", res[0].Redacted)
	}
	if strings.Contains(res[0].Redacted, "MIIE") {
		t.Fatalf("redacted leaked body: %q", res[0].Redacted)
	}
}
