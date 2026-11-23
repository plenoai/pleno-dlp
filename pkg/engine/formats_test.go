package engine

import (
	"bytes"
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
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

const formatVerifyProbeType = detectors.DetectorType(1<<29 + 1)

type formatVerifyProbe struct{}

func (formatVerifyProbe) Type() detectors.DetectorType { return formatVerifyProbeType }
func (formatVerifyProbe) Keywords() []string           { return []string{"nativekw"} }
func (formatVerifyProbe) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return nil, nil
}

func scanWith(t *testing.T, opts Options, data []byte) []Result {
	t.Helper()
	collector := &resultCollector{}
	eng := NewWithDetectors([]detectors.Detector{formatVerifyProbe{}}, opts, collector)
	if _, err := eng.RunWithStats(context.Background(), &bytesSource{chunk: &sources.Chunk{SourceName: "t", Data: data}}); err != nil {
		t.Fatal(err)
	}
	return collector.snapshot()
}

// A format with a Verify hook is verified by the engine against the
// candidate's window (so a paired id resolves), records the format's own
// assurance even on a detector without a policy, and stays offline under
// NoVerify or when its assurance is below the caller's minimum (#934).
func TestEngineVerifiesFormatsWithHooks(t *testing.T) {
	var calls int
	detectors.RegisterFormats(formatVerifyProbeType, &detectors.Format{
		ID: "test.verify-format", Keywords: []string{"vprobe_"}, Pattern: `\b(vprobe_[A-Za-z0-9]{16})\b`,
		Assurance: detectors.AssuranceResponseConfirmed,
		Verify: func(_ context.Context, secret string, data []byte) (bool, error) {
			calls++
			return bytes.Contains(data, []byte("pair_id=ok")), nil
		},
	})
	data := []byte("pair_id=ok\nkey = vprobe_Q7cK2mZp9LsW4tRb\n")
	got := scanWith(t, Options{}, data)
	if len(got) != 1 || !got[0].Verified || got[0].VerificationAssurance != detectors.AssuranceResponseConfirmed ||
		got[0].ExtraData["verification"] != "format" || got[0].VerificationErr != nil {
		t.Fatalf("verified format finding: %+v", got)
	}
	calls = 0
	if got := scanWith(t, Options{NoVerify: true}, data); len(got) != 1 || got[0].Verified || calls != 0 {
		t.Fatalf("NoVerify: calls=%d %+v", calls, got)
	}
	if got := scanWith(t, Options{MinimumVerificationAssurance: detectors.AssuranceProviderConfirmed}, data); len(got) != 1 || got[0].Verified || calls != 0 {
		t.Fatalf("assurance gate: calls=%d %+v", calls, got)
	}
}
