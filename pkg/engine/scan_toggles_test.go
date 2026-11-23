package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestNoArchiveExtractionScansArchiveOpaquely(t *testing.T) {
	akia := "AKIAIOSFODNN7EXAMPLE"
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("config.env")
	_, _ = w.Write([]byte("AWS_KEY=" + akia + "\n"))
	_ = zw.Close()

	for _, tc := range []struct {
		noExtract bool
		want      int
	}{{false, 1}, {true, 0}} {
		sink := &recordingSink{}
		eng := NewWithDetectors([]detectors.Detector{fakeDetector{needle: akia}}, Options{Concurrency: 1, NoArchiveExtraction: tc.noExtract}, sink)
		if err := eng.Run(context.Background(), fakeSource{data: buf.Bytes()}); err != nil {
			t.Fatal(err)
		}
		sink.mu.Lock()
		got := len(sink.findings)
		sink.mu.Unlock()
		if got != tc.want {
			t.Fatalf("NoArchiveExtraction=%v: %d findings, want %d", tc.noExtract, got, tc.want)
		}
	}
}

func TestInlineAllowTokensOption(t *testing.T) {
	const secret = "AKIASECRETVALUE"
	data := "a=1\nkey=AKIASECRETVALUE // NOSONAR\n"
	if inlineAllowedIn([]byte(data), []byte(secret)) {
		t.Fatal("custom token must not apply without configuration")
	}
	tokens := compileInlineTokens([]string{"", "NOSONAR"})
	if len(tokens) != 1 {
		t.Fatalf("empty token kept: %q", tokens)
	}
	if !inlineAllowedIn([]byte(data), []byte(secret), tokens...) {
		t.Fatal("configured token not honored")
	}
	if inlineAllowedIn([]byte("// NOSONAR\nkey=AKIASECRETVALUE\n"), []byte(secret), tokens...) {
		t.Fatal("custom tokens are same-line only")
	}

	sink := &recordingSink{}
	eng := NewWithDetectors([]detectors.Detector{fakeDetector{needle: secret}}, Options{Concurrency: 1, InlineAllowTokens: []string{"NOSONAR"}}, sink)
	if err := eng.Run(context.Background(), fakeSource{data: []byte(data)}); err != nil {
		t.Fatal(err)
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.findings) != 1 || !sink.findings[0].InlineAllowed {
		t.Fatalf("finding not marked InlineAllowed: %+v", sink.findings)
	}
}

func TestDetectorStatsOption(t *testing.T) {
	const secret = "AKIASTATSVALUE"
	run := func(enabled bool) []DetectorStat {
		eng := NewWithDetectors([]detectors.Detector{fakeDetector{needle: secret}}, Options{Concurrency: 1, DetectorStats: enabled}, &recordingSink{})
		if err := eng.Run(context.Background(), fakeSource{data: []byte("k=" + secret + "\n")}); err != nil {
			t.Fatal(err)
		}
		return eng.DetectorStats()
	}
	if got := run(false); got != nil {
		t.Fatalf("stats without option: %+v", got)
	}
	got := run(true)
	if len(got) != 1 || got[0].Detector != detectors.AWS || got[0].Calls < 1 || got[0].Results < 1 {
		t.Fatalf("stats %+v", got)
	}
}
