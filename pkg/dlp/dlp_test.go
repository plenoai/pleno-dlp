package dlp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Split so the repository's own pre-commit scan does not flag the fixture.
const slackWebhook = "https://hooks.slack.com/services/" + "T024BE7LD/B024BE7LD/abcdefghijklmnopqrstuvwx"

func TestScanBytesOfflineRedactsByDefault(t *testing.T) {
	got, err := ScanBytes(context.Background(), []byte("url="+slackWebhook), ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Detector != "SlackWebhook" {
		t.Fatalf("want one SlackWebhook finding, got %+v", got)
	}
	f := got[0]
	if f.Raw != "" || f.RawV2 != "" || strings.Contains(f.Redacted, slackWebhook) {
		t.Fatalf("plaintext leaked without IncludeRaw: %+v", f)
	}
	if f.Verified || f.Verdict != "unverified" {
		t.Fatalf("offline scan must not verify: %+v", f)
	}
}

func TestScanBytesIncludeRawAndDetectorFilter(t *testing.T) {
	got, err := ScanBytes(context.Background(), []byte(slackWebhook), ScanOptions{IncludeRaw: true, Detectors: []string{"SlackWebhook"}})
	if err != nil || len(got) != 1 || got[0].Raw != slackWebhook {
		t.Fatalf("got %+v, %v", got, err)
	}
	got, err = ScanBytes(context.Background(), []byte(slackWebhook), ScanOptions{Detectors: []string{"AWS"}})
	if err != nil || len(got) != 0 {
		t.Fatalf("filter ignored: %+v, %v", got, err)
	}
	if _, err := ScanBytes(context.Background(), nil, ScanOptions{Detectors: []string{"NoSuch"}}); !errors.Is(err, ErrUnknownDetector) {
		t.Fatalf("want ErrUnknownDetector, got %v", err)
	}
}

func TestScanPathsReportsLocation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.env")
	if err := os.WriteFile(p, []byte("a=1\nb=2\nhook="+slackWebhook+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ScanPaths(context.Background(), []string{dir}, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Path != p || got[0].Line != 3 {
		t.Fatalf("want %s:3, got %+v", p, got)
	}
	if _, err := ScanPaths(context.Background(), []string{filepath.Join(dir, "missing")}, ScanOptions{}); err == nil {
		t.Fatal("missing path must error")
	}
}

func TestVerifyAndRevokeGates(t *testing.T) {
	ctx := context.Background()
	if _, err := Verify(ctx, "NoSuch", "x"); !errors.Is(err, ErrUnknownDetector) {
		t.Fatalf("got %v", err)
	}
	var noVerify, noRevoke string
	for _, d := range Detectors() {
		if !d.CanVerify && noVerify == "" {
			noVerify = d.Name
		}
		if !d.CanRevoke && noRevoke == "" {
			noRevoke = d.Name
		}
	}
	if _, err := Verify(ctx, noVerify, "x"); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v", err)
	}
	if _, err := Revoke(ctx, "GitHub", "x", RevokeOptions{}); !errors.Is(err, ErrNotConfirmed) {
		t.Fatalf("unconfirmed revoke: %v", err)
	}
	if _, err := Revoke(ctx, "GitHub", "x", RevokeOptions{Confirm: true, DryRun: true}); !errors.Is(err, ErrNotConfirmed) {
		t.Fatalf("ambiguous revoke: %v", err)
	}
	if _, err := Revoke(ctx, noRevoke, "x", RevokeOptions{DryRun: true}); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v", err)
	}
	r, err := Revoke(ctx, "GitHub", "x", RevokeOptions{DryRun: true})
	if err != nil || !r.DryRun || r.Revoked {
		t.Fatalf("dry run: %+v %v", r, err)
	}
}

func TestDetectorsSortedWithCapabilities(t *testing.T) {
	ds := Detectors()
	if len(ds) < 100 || !sort.SliceIsSorted(ds, func(i, j int) bool { return ds[i].Name < ds[j].Name }) {
		t.Fatalf("unexpected detector list (%d)", len(ds))
	}
	for _, d := range ds {
		if d.Name == "GitHub" && (!d.CanVerify || !d.CanRevoke) {
			t.Fatalf("GitHub capabilities: %+v", d)
		}
	}
}

// TestJSONContractFrozen pins the wire field names shared with the C ABI
// and the Python/Node bindings. Renaming or removing a field is a breaking
// change that requires an APIVersion major bump.
func TestJSONContractFrozen(t *testing.T) {
	cases := map[string]struct {
		v    any
		want []string
	}{
		"Finding":       {Finding{}, []string{"detector", "verified", "verdict", "assurance", "severity", "redacted", "raw", "raw_v2", "path", "line", "verify_error", "extra_data"}},
		"ScanOptions":   {ScanOptions{}, []string{"verify", "include_raw", "detectors", "concurrency", "max_file_size"}},
		"VerifyResult":  {VerifyResult{}, []string{"detector", "verified", "error"}},
		"RevokeOptions": {RevokeOptions{}, []string{"confirm", "dry_run"}},
		"RevokeResult":  {RevokeResult{}, []string{"detector", "revoked", "dry_run", "revoked_at", "provider_id", "note", "outcome"}},
		"Detector":      {Detector{}, []string{"name", "keywords", "can_verify", "can_revoke"}},
	}
	for name, c := range cases {
		typ := reflect.TypeOf(c.v)
		var got []string
		for i := 0; i < typ.NumField(); i++ {
			got = append(got, strings.Split(typ.Field(i).Tag.Get("json"), ",")[0])
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s JSON fields changed: got %v want %v", name, got, c.want)
		}
		if _, err := json.Marshal(c.v); err != nil {
			t.Error(err)
		}
	}
}
