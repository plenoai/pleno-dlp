package output

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestAuditHTMLOrderingMetadataAndRedaction(t *testing.T) {
	var buf bytes.Buffer
	s, err := NewSink("audit-html", &buf, "v9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	s.(AuditMetaSetter).SetAuditMeta(func(m *AuditMeta) {
		m.Source = "filesystem"
		m.Flags = []string{"format", "no-verify"}
		m.Chunks, m.Bytes = 3, 42
	})
	raw := "AKIA" + "QWERTYUIOPASDFGH"
	mk := func(verified bool, verr error, sev detectors.Severity, path string) engine.Finding {
		return engine.Finding{
			Detector: detectors.AWS,
			Result: detectors.Result{DetectorType: detectors.AWS, Raw: []byte(raw), Verified: verified,
				VerificationErr: verr, Severity: sev, Redacted: "AKIA****"},
			Chunk: &sources.Chunk{SourceType: sources.SourceFilesystem, SourceMetadata: sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: path}}},
		}
	}
	s.Emit(mk(false, nil, detectors.SeverityCritical, "c-unverified"))
	s.Emit(mk(false, errors.New("timeout"), detectors.SeverityLow, "b-indeterminate"))
	s.Emit(mk(true, nil, detectors.SeverityLow, "a-verified"))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, raw) {
		t.Fatal("audit report leaks raw secret")
	}
	a, b, c := strings.Index(out, "a-verified"), strings.Index(out, "b-indeterminate"), strings.Index(out, "c-unverified")
	if a < 0 || !(a < b && b < c) {
		t.Fatalf("validation ordering wrong: %d %d %d", a, b, c)
	}
	for _, want := range []string{"Run ID", "filesystem", "v9.9.9", "--no-verify", "3 / 42", "Validation summary (3 findings)"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q", want)
		}
	}
}
