package alerts

import (
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
)

func TestParsePolicyValues(t *testing.T) {
	if _, err := ParseOn("sometimes"); err == nil {
		t.Fatal("want error")
	}
	if f, _ := ParseFindingFilter("ONLY-ACTIVE"); f != FilterOnlyActive {
		t.Fatalf("got %q", f)
	}
	if _, err := ParseDetail("verbose"); err == nil {
		t.Fatal("want error")
	}
	for _, bad := range []string{"ftp://x/y", "/relative", "not a url"} {
		if _, err := ParseReportURL(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if u, err := ParseReportURL(" https://ci.example/run/1 "); err != nil || u != "https://ci.example/run/1" {
		t.Fatalf("got %q %v", u, err)
	}
}

func TestShouldSend(t *testing.T) {
	cases := []struct {
		p               Policy
		filtered, total int
		want            bool
	}{
		{Policy{On: OnFindings, PreventEmpty: true}, 0, 0, false},
		{Policy{On: OnFindings, PreventEmpty: true}, 0, 3, false},
		{Policy{On: OnFindings, PreventEmpty: false}, 0, 3, true},
		{Policy{On: OnFindings, PreventEmpty: true}, 1, 3, true},
		{Policy{On: OnAlways, PreventEmpty: true}, 0, 0, true},
	}
	for i, c := range cases {
		if got := c.p.ShouldSend(c.filtered, c.total); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}

func TestCollectorFindingFilter(t *testing.T) {
	mk := func(verified, backed, mapped bool) engine.Finding {
		r := detectors.Result{DetectorType: detectors.DetectorType(1), Severity: detectors.SeverityHigh, Verified: verified}
		if mapped {
			r.ExtraData = map[string]string{accessMapKey: "{}"}
		}
		return engine.Finding{Result: r, VerifierBacked: backed}
	}
	inputs := []engine.Finding{
		mk(true, true, true),    // active + mapped
		mk(true, true, false),   // active
		mk(false, true, false),  // inactive (provider rejected)
		mk(false, false, false), // no verifier: never validated
	}
	want := map[FindingFilter]int{FilterAll: 4, FilterExcludeInactive: 3, FilterOnlyActive: 2, FilterAccessMapOnly: 1}
	for f, n := range want {
		c := &Collector{Inner: &nopSink{}, Filter: f}
		for _, in := range inputs {
			c.Emit(in)
		}
		if got := len(c.Findings()); got != n {
			t.Errorf("%s: got %d want %d", f, got, n)
		}
		if c.ScanTotal() != 4 {
			t.Errorf("%s: total %d", f, c.ScanTotal())
		}
	}
	// --no-verify: an unverified verifier-backed finding is not "inactive".
	c := &Collector{Inner: &nopSink{}, Filter: FilterExcludeInactive, VerifyDisabled: true}
	for _, in := range inputs {
		c.Emit(in)
	}
	if got := len(c.Findings()); got != 4 {
		t.Fatalf("no-verify exclude-inactive: got %d", got)
	}
}

func TestDetailAndReportURL(t *testing.T) {
	fs := make([]Finding, 30)
	for i := range fs {
		fs[i] = Finding{Detector: "AWS", Severity: "high", Redacted: "AKIA****"}
	}
	s := Policy{Detail: DetailAuto, ReportURL: "https://ci.example/run/9"}.Apply(BuildSummary("v", "filesystem", detectors.SeverityInfo, fs))
	if s.Detail != "summary" {
		t.Fatalf("auto over threshold resolved to %q", s.Detail)
	}
	body, _ := Payload(FormatSlack, s)
	if strings.Contains(string(body), "AKIA****") || !strings.Contains(string(body), "https://ci.example/run/9") {
		t.Fatalf("summary payload: %s", body)
	}
	s = Policy{Detail: DetailFull}.Apply(BuildSummary("v", "filesystem", detectors.SeverityInfo, fs[:2]))
	body, _ = Payload(FormatSlack, s)
	if !strings.Contains(string(body), "AKIA****") {
		t.Fatalf("detail payload: %s", body)
	}
	gen, _ := Payload(FormatGeneric, Policy{ReportURL: "https://r.example/"}.Apply(BuildSummary("v", "x", detectors.SeverityInfo, nil)))
	if !strings.Contains(string(gen), `"report_url":"https://r.example/"`) {
		t.Fatalf("generic: %s", gen)
	}
}
