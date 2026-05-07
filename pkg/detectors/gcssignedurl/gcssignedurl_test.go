package gcssignedurl

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func futureDate() string {
	return time.Now().UTC().Format("20060102T150405Z")
}

func TestFromData_Positive(t *testing.T) {
	cred := url.QueryEscape("svc@proj.iam.gserviceaccount.com/" + futureDate()[:8] + "/auto/storage/goog4_request")
	urlStr := "https://storage.googleapis.com/my-bucket/path/key.bin" +
		"?X-Goog-Algorithm=GOOG4-RSA-SHA256" +
		"&X-Goog-Credential=" + cred +
		"&X-Goog-Date=" + futureDate() +
		"&X-Goog-Expires=900" +
		"&X-Goog-SignedHeaders=host" +
		"&X-Goog-Signature=" + strings.Repeat("a", 128)
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(urlStr))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if got := res[0].ExtraData["service_account"]; got != "svc@proj.iam.gserviceaccount.com" {
		t.Fatalf("sa: %q", got)
	}
	if res[0].Severity != detectors.SeverityCritical {
		t.Fatalf("severity: %v", res[0].Severity)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("https://storage.googleapis.com/b/k"))
	if len(res) != 0 {
		t.Fatalf("expected 0")
	}
}
