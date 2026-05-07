package smtp

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestFromData_Positive(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("smtp://app:hunter2@mail.example.com:587"))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != "hunter2" {
		t.Fatalf("password: %q", res[0].Raw)
	}
	if res[0].Severity != detectors.SeverityMedium {
		t.Fatalf("severity: %v", res[0].Severity)
	}
}

func TestFromData_SmtpsScheme(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("smtps://relay:p4ss@smtp.example.com:465"))
	if len(res) != 1 {
		t.Fatalf("expected 1")
	}
	if string(res[0].Raw) != "p4ss" {
		t.Fatalf("password: %q", res[0].Raw)
	}
}

func TestFromData_NoUserinfo(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("smtp://mail.example.com:25"))
	if len(res) != 0 {
		t.Fatalf("expected 0")
	}
}
