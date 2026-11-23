package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

type fakeValidateDetector struct{ gotVerify bool }

func (*fakeValidateDetector) Keywords() []string           { return []string{"tok_"} }
func (*fakeValidateDetector) Type() detectors.DetectorType { return detectors.GitHub }
func (f *fakeValidateDetector) FromData(_ context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	f.gotVerify = verify
	s := strings.TrimSpace(string(data))
	if !strings.HasPrefix(s, "tok_") {
		return nil, nil
	}
	return []detectors.Result{{DetectorType: detectors.GitHub, Raw: []byte(s), Redacted: "tok_...", Verified: s == "tok_live"}}, nil
}

func runValidateWith(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	fake := &fakeValidateDetector{}
	prev := validateDetectors
	validateDetectors = func() []detectors.Detector { return []detectors.Detector{fake} }
	t.Cleanup(func() { validateDetectors = prev })
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetIn(strings.NewReader(stdin))
	Root.SetArgs(append([]string{"validate"}, args...))
	t.Cleanup(func() {
		Root.SetArgs(nil)
		Root.SetIn(nil)
		Root.SetOut(nil)
		validateOpts.secret, validateOpts.detector, validateOpts.format = "", "", "table"
	})
	err := Root.Execute()
	if !fake.gotVerify && err == nil {
		t.Fatal("detector ran without verify")
	}
	return out.String(), err
}

func TestValidateVerifiedFromStdin(t *testing.T) {
	out, err := runValidateWith(t, "tok_live\n", "--detector", "github", "--secret", "-", "--format", "json")
	if err != nil {
		t.Fatalf("err=%v out=%s", err, out)
	}
	if strings.Contains(out, "tok_live") || !strings.Contains(out, `"verified":true`) {
		t.Fatalf("bad output (must be redacted): %s", out)
	}
}

func TestValidateUnverifiedExitsNonZero(t *testing.T) {
	_, err := runValidateWith(t, "", "--detector", "GitHub", "--secret", "tok_dead")
	if !errors.Is(err, errVerifyFailed) {
		t.Fatalf("want errVerifyFailed, got %v", err)
	}
}

func TestValidateRejectsUnknownAndNonMatching(t *testing.T) {
	if _, err := runValidateWith(t, "", "--detector", "nope", "--secret", "x"); err == nil || !strings.Contains(err.Error(), "unknown detector") {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := runValidateWith(t, "", "--detector", "github", "--secret", "zzz"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("non-matching: %v", err)
	}
}
