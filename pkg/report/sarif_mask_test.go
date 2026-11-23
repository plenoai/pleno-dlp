package report

import (
	"strings"
	"testing"

	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
)

// TestImportSARIFMasksSecretInMessage pins #846: a third-party SARIF whose
// message.text embeds the matched secret is masked at import.
func TestImportSARIFMasksSecretInMessage(t *testing.T) {
	in := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"other"}},"results":[{"ruleId":"github-pat","level":"error","message":{"text":"found token ` + secret + ` in config"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"x.txt"},"region":{"startLine":1}}}]}]}]}`
	got, err := Import(strings.NewReader(in), "s.sarif")
	if err != nil || len(got) != 1 {
		t.Fatalf("got %+v err=%v", got, err)
	}
	msg := got[0].Redacted
	if strings.Contains(msg, secret) {
		t.Fatalf("secret leaked into message: %q", msg)
	}
	if !strings.HasPrefix(msg, "found token ") || !strings.HasSuffix(msg, " in config") {
		t.Fatalf("surrounding text lost: %q", msg)
	}
}
