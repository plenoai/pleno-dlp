package engine

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// offlineScanBytesProbe records how the engine invoked it so tests can assert
// keyword gating and the forced-offline contract of the ScanBytes API.
type offlineScanBytesProbe struct {
	keyword    string
	raw        []byte
	calls      atomic.Int64
	lastVerify atomic.Bool
}

func (d *offlineScanBytesProbe) Type() detectors.DetectorType { return detectors.AWS }
func (d *offlineScanBytesProbe) Keywords() []string           { return []string{d.keyword} }
func (d *offlineScanBytesProbe) FromData(_ context.Context, verify bool, _ []byte) ([]detectors.Result, error) {
	d.calls.Add(1)
	d.lastVerify.Store(verify)
	return []detectors.Result{{DetectorType: detectors.AWS, Raw: append([]byte(nil), d.raw...)}}, nil
}

func TestOfflineScanBytesCollectsFindings(t *testing.T) {
	probe := &offlineScanBytesProbe{keyword: "secret", raw: []byte("secret-token")}

	got, err := ScanBytesWithDetectors(context.Background(), []detectors.Detector{probe}, []byte("prefix secret-token suffix"), Options{})
	if err != nil {
		t.Fatalf("ScanBytesWithDetectors: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("results: want 1, got %d", len(got))
	}
	if got[0].DetectorType != detectors.AWS {
		t.Errorf("detector type: want %s, got %s", detectors.AWS, got[0].DetectorType)
	}
	if string(got[0].Raw) != "secret-token" {
		t.Errorf("raw: want %q, got %q", "secret-token", string(got[0].Raw))
	}
}

func TestOfflineScanBytesForcesNoVerify(t *testing.T) {
	probe := &offlineScanBytesProbe{keyword: "secret", raw: []byte("secret-token")}

	if _, err := ScanBytesWithDetectors(context.Background(), []detectors.Detector{probe}, []byte("secret-token"), Options{NoVerify: false}); err != nil {
		t.Fatalf("ScanBytesWithDetectors: %v", err)
	}
	if probe.lastVerify.Load() {
		t.Fatal("ScanBytes must force NoVerify so detectors never hit the network")
	}
}

func TestOfflineScanBytesSkipsAbsentKeyword(t *testing.T) {
	probe := &offlineScanBytesProbe{keyword: "not-present", raw: []byte("unused")}

	got, err := ScanBytesWithDetectors(context.Background(), []detectors.Detector{probe}, []byte("plain text with no trigger"), Options{})
	if err != nil {
		t.Fatalf("ScanBytesWithDetectors: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("results: want 0, got %d", len(got))
	}
	if calls := probe.calls.Load(); calls != 0 {
		t.Fatalf("detector calls: want 0, got %d", calls)
	}
}

func TestOfflineScanBytesEmptyInput(t *testing.T) {
	got, err := ScanBytes(context.Background(), nil, Options{})
	if err != nil {
		t.Fatalf("ScanBytes: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("results: want 0, got %d", len(got))
	}
}
