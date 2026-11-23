package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectorsCheck(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "rules.json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	run := func(path string) (string, error) {
		resetCommandFlags(t)
		var out bytes.Buffer
		Root.SetOut(&out)
		Root.SetErr(&out)
		Root.SetArgs([]string{"detectors", "check", "--rules", path})
		err := Root.Execute()
		return out.String(), err
	}
	ok := write(`[{"name":"acme","keywords":["acme_"],"regex":"acme_[a-z0-9]{12}","examples":["token=acme_abcdef123456"],"negative_examples":["acme_short"]}]`)
	if out, err := run(ok); err != nil || !strings.Contains(out, "0 failure(s)") {
		t.Fatalf("passing rules: %v\n%s", err, out)
	}
	bad := write(`[{"name":"acme","keywords":["acme_"],"regex":"acme_[a-z0-9]{12}","examples":["nothing here"],"negative_examples":["acme_abcdef123456"]}]`)
	out, err := run(bad)
	if err == nil || strings.Count(out, "FAIL") != 2 {
		t.Fatalf("failing rules: %v\n%s", err, out)
	}
}
