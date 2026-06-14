//go:build detector_unit

package awss3presigned

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func futureDate() string {
	return time.Now().UTC().Format("20060102T150405Z")
}

func pastDate() string {
	return time.Now().UTC().Add(-2 * time.Hour).Format("20060102T150405Z")
}

func TestFromData_VirtualHostStyle(t *testing.T) {
	url := "https://my-bucket.s3.us-east-1.amazonaws.com/object.bin" +
		"?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F" + futureDate()[:8] + "%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=" + futureDate() +
		"&X-Amz-Expires=900" +
		"&X-Amz-SignedHeaders=host" +
		"&X-Amz-Signature=" + strings.Repeat("a", 64)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(url))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if got := res[0].ExtraData["access_key_id"]; got != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("akid: %q", got)
	}
	if got := res[0].ExtraData["region"]; got != "us-east-1" {
		t.Fatalf("region: %q", got)
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("severity: %v", res[0].Severity)
	}
}

func TestFromData_Expired(t *testing.T) {
	url := "https://b.s3.us-east-1.amazonaws.com/o" +
		"?X-Amz-Algorithm=AWS4-HMAC-SHA256" +
		"&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F" + pastDate()[:8] + "%2Fus-east-1%2Fs3%2Faws4_request" +
		"&X-Amz-Date=" + pastDate() +
		"&X-Amz-Expires=60" +
		"&X-Amz-SignedHeaders=host" +
		"&X-Amz-Signature=" + strings.Repeat("a", 64)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(url))
	if len(res) != 1 {
		t.Fatalf("expected 1")
	}
	if res[0].Severity != detectors.SeverityHigh {
		t.Fatalf("expected High for expired url, got %v", res[0].Severity)
	}
	if res[0].ExtraData["expired"] != "true" {
		t.Fatalf("expired flag missing")
	}
}

func TestFromData_NoSignature(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("https://b.s3.amazonaws.com/o"))
	if len(res) != 0 {
		t.Fatalf("expected 0")
	}
}
