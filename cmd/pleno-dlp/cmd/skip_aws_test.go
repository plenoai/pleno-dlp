package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors/aws"
)

func TestApplySkipAWSAccounts(t *testing.T) {
	t.Cleanup(func() { _ = aws.SetSkipAccounts(nil) })
	p := filepath.Join(t.TempDir(), "c.txt")
	if err := os.WriteFile(p, []byte("# canaries\n111122223333  # prod decoy\n\n444455556666\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := applySkipAWSAccounts([]string{"999900001111"}, p); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"111122223333", "444455556666", "999900001111", "171436882533"} {
		if !aws.IsSkippedAccount(id) {
			t.Errorf("%s not skipped", id)
		}
	}
	if err := applySkipAWSAccounts([]string{"abc"}, ""); err == nil {
		t.Fatal("invalid id accepted")
	}
	if err := applySkipAWSAccounts(nil, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file accepted")
	}
}
