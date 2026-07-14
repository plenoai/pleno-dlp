package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/bench/git-history/fixture"
)

func TestParsePlenoCanary(t *testing.T) {
	meta := testMetadata()
	sum := sha256.Sum256([]byte(meta.Canary))
	records := []map[string]any{{
		"detector":    "GitHub",
		"secret_hash": hex.EncodeToString(sum[:]),
		"source": map[string]any{"metadata": map[string]any{
			"file": meta.CanaryPath, "commit": meta.CanaryCommit,
		}},
	}}
	data, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}

	got, err := parsePlenoCanary(data, meta)
	if err != nil {
		t.Fatal(err)
	}
	assertCanaryObservation(t, got, meta)
}

func TestParseTruffleCanary(t *testing.T) {
	meta := testMetadata()
	record := map[string]any{
		"DetectorName": "Github",
		"Raw":          base64.StdEncoding.EncodeToString([]byte(meta.Canary)),
		"SourceMetadata": map[string]any{"Data": map[string]any{
			"Git": map[string]any{"commit": meta.CanaryCommit, "file": meta.CanaryPath},
		}},
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}

	got, err := parseTruffleCanary(append(data, '\n'), meta)
	if err != nil {
		t.Fatal(err)
	}
	assertCanaryObservation(t, got, meta)
}

func TestMedianAndLinearSlope(t *testing.T) {
	if got := median([]float64{4, 1, 3, 2}); got != 2.5 {
		t.Fatalf("median=%v want=2.5", got)
	}
	windows := []sourceWindow{{ChunksPerSecond: 100}, {ChunksPerSecond: 90}, {ChunksPerSecond: 80}}
	if got := linearSlope(windows); got != -10 {
		t.Fatalf("slope=%v want=-10", got)
	}
	if got := medianWindowThroughput(windows); got != 90 {
		t.Fatalf("window median=%v want=90", got)
	}
}

func TestRunToolBatchMeetsMinimumDuration(t *testing.T) {
	meta := testMetadata()
	spec := toolSpec{
		name:      "echo",
		bin:       "/bin/echo",
		allowExit: map[int]bool{0: true},
		parse: func([]byte, fixture.Metadata) (canaryObservation, error) {
			return canaryObservation{Total: 1, Matches: 1, File: meta.CanaryPath, Commit: meta.CanaryCommit}, nil
		},
	}
	want := 25 * time.Millisecond
	_, wallSeconds, iterations, err := runToolBatch(context.Background(), spec, meta, 1, want, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(wallSeconds*float64(time.Second)) < want {
		t.Fatalf("sample=%v want at least %v", time.Duration(wallSeconds*float64(time.Second)), want)
	}
	if iterations < 1 {
		t.Fatalf("iterations=%d want at least 1", iterations)
	}
}

func TestMeasureSourceUsesThreeWindowMediansAfterStartup(t *testing.T) {
	meta, err := fixture.Generate(context.Background(), filepath.Join(t.TempDir(), "fixture.git"), fixture.Spec{Commits: 70, Files: 8})
	if err != nil {
		t.Fatal(err)
	}
	result, err := measureSource(context.Background(), meta, 10)
	if err != nil {
		t.Fatal(err)
	}
	if result.StabilityWindows != 3 || result.EarlyWindowStart != 11 || result.EarlyWindowEnd != 40 || result.TailWindowStart != 41 || result.TailWindowEnd != 70 {
		t.Fatalf("stability bands=%+v", result)
	}
	want := medianWindowThroughput(result.Windows[4:7]) / medianWindowThroughput(result.Windows[1:4])
	if result.TailEarlyRatio != want {
		t.Fatalf("ratio=%v want=%v", result.TailEarlyRatio, want)
	}
	if result.ScalingPrefixChunks != 30 || result.FullToPrefixRatio <= 1 {
		t.Fatalf("scaling prefix=%d ratio=%v", result.ScalingPrefixChunks, result.FullToPrefixRatio)
	}
}

func testMetadata() fixture.Metadata {
	return fixture.Metadata{
		Canary:       fixture.CanaryToken(),
		CanaryCommit: "0123456789abcdef",
		CanaryPath:   "d0000/s01/f00000001.txt",
	}
}

func assertCanaryObservation(t *testing.T, got canaryObservation, meta fixture.Metadata) {
	t.Helper()
	if got.Total != 1 || got.Matches != 1 || got.File != meta.CanaryPath || got.Commit != meta.CanaryCommit {
		t.Fatalf("observation=%+v", got)
	}
}
