package engine

import (
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// formatProbeType is outside the enum so the test's global format
// registration cannot collide with a real detector.
const formatProbeType = detectors.DetectorType(1 << 29)

type formatProbe struct{ native []byte }

func (formatProbe) Type() detectors.DetectorType { return formatProbeType }
func (formatProbe) Keywords() []string           { return []string{"nativekw"} }
func (p formatProbe) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	if p.native == nil {
		return nil, nil
	}
	return []detectors.Result{{DetectorType: formatProbeType, Raw: p.native, Redacted: "n…"}}, nil
}

// Supplementary formats run after the native detector, are scheduled by
// their own keywords (the native keyword is absent from the input), are
// never verified, and do not duplicate a secret the detector reported.
func TestEngineRunsRegisteredFormats(t *testing.T) {
	detectors.RegisterFormats(formatProbeType, &detectors.Format{
		ID: "test.probe-format", Keywords: []string{"probe_"}, Pattern: `\b(probe_[A-Za-z0-9]{16})\b`,
	})
	data := []byte("x = probe_Q7cK2mZp9LsW4tRb\ny = probe_Hn3Vd8Fj1Xq6Gy5E\n")
	got, err := ScanBytesWithDetectors(context.Background(), []detectors.Detector{formatProbe{}}, data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(got), got)
	}
	for _, f := range got {
		if f.Verified || f.ExtraData["format"] != "test.probe-format" || f.ExtraData["verification"] != "not-attempted" {
			t.Fatalf("unexpected format finding %+v", f)
		}
	}

	dup := formatProbe{native: []byte("probe_Q7cK2mZp9LsW4tRb")}
	got, err = ScanBytesWithDetectors(context.Background(), []detectors.Detector{dup}, data, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("native + format: got %d findings, want 2 (no duplicate): %+v", len(got), got)
	}
}
