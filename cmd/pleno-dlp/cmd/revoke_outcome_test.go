package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/audit"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// TestRevokeAcceptedIsNotSuccess pins #859: an accepted-only revoke is
// rendered as ACCEPTED, recorded as outcome=accepted, and maps to the
// distinct unconfirmed error that still satisfies IsRevokeFailed.
func TestRevokeAcceptedIsNotSuccess(t *testing.T) {
	if !IsRevokeFailed(errRevokeUnconfirmed) || !IsRevokeUnconfirmed(errRevokeUnconfirmed) || IsRevokeUnconfirmed(errRevokeFailed) {
		t.Fatal("error classification broken")
	}
	var errBuf bytes.Buffer
	Root.SetErr(&errBuf)
	t.Cleanup(func() { Root.SetErr(nil) })
	emitRevoke(Root, "table", revokeRecord{Detector: "HuggingFace", RedactedSecret: "hf_***", Outcome: string(detectors.RevokeAccepted), Error: "queued"})
	if !strings.Contains(errBuf.String(), "ACCEPTED") || strings.Contains(errBuf.String(), "OK:") {
		t.Fatalf("table output = %q", errBuf.String())
	}
	rec := audit.New(audit.Attempt{Path: audit.PathSingle, Detector: "HuggingFace", Secret: "s", Outcome: detectors.RevokeAccepted})
	b, _ := json.Marshal(rec)
	if !strings.Contains(string(b), `"outcome":"accepted"`) || strings.Contains(string(b), `"revoked":true`) {
		t.Fatalf("audit = %s", b)
	}
}
