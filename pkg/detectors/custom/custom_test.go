//go:build detector_unit

package custom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

func TestCompile_RequiresFields(t *testing.T) {
	cases := []struct {
		name    string
		rule    Rule
		wantErr string
	}{
		{"no name", Rule{Keywords: []string{"x"}, Regex: "x"}, "name"},
		{"no keywords", Rule{Name: "n", Regex: "x"}, "keyword"},
		{"no regex", Rule{Name: "n", Keywords: []string{"x"}}, "regex"},
		{"bad regex", Rule{Name: "n", Keywords: []string{"x"}, Regex: "(unclosed"}, "regex"},
		{"bad severity", Rule{Name: "n", Keywords: []string{"x"}, Regex: "x", Severity: "extreme"}, "severity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(tc.rule)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestFromData_MatchesAndRedacts(t *testing.T) {
	d, err := Compile(Rule{
		Name:     "ACME Key",
		Keywords: []string{"ACME_"},
		Regex:    `ACME_[A-Z0-9]{20}`,
		Severity: "high",
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	results, err := d.FromData(context.Background(), false,
		[]byte("config:\n  api_key: ACME_QWERTYUIOPASDFGHJKLZ\n"))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result; got %d", len(results))
	}
	r := results[0]
	if string(r.Raw) != "ACME_QWERTYUIOPASDFGHJKLZ" {
		t.Errorf("Raw = %q", r.Raw)
	}
	if r.Severity != detectors.SeverityHigh {
		t.Errorf("Severity = %v", r.Severity)
	}
	if r.ExtraData["custom_rule"] != "ACME Key" {
		t.Errorf("ExtraData[custom_rule] = %q", r.ExtraData["custom_rule"])
	}
	if !strings.HasPrefix(r.Redacted, "ACME") {
		t.Errorf("Redacted = %q", r.Redacted)
	}
}

func TestFromData_EntropyGate(t *testing.T) {
	// EntropyMin=3.5 rejects 'ACME_AAAAAAAAAAAAAAAAAAAA' (one repeated
	// char ≈ 0 bits) but accepts a real-looking high-entropy candidate.
	d, _ := Compile(Rule{
		Name:       "ACME Entropy",
		Keywords:   []string{"ACME_"},
		Regex:      `ACME_[A-Z0-9]{20}`,
		EntropyMin: 3.5,
	})

	low := []byte("ACME_AAAAAAAAAAAAAAAAAAAA")
	high := []byte("ACME_QWERTYUIOPASDFGHJKLZ")

	res, _ := d.FromData(context.Background(), false, low)
	if len(res) != 0 {
		t.Errorf("low-entropy candidate should be filtered; got %d", len(res))
	}
	res, _ = d.FromData(context.Background(), false, high)
	if len(res) != 1 {
		t.Errorf("high-entropy candidate should match; got %d", len(res))
	}
}

func TestVerify_200IsVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ACME_QWERTYUIOPASDFGHJKLZ" {
			t.Errorf("Authorization header = %q", got)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	d, _ := Compile(Rule{
		Name:      "ACME Verify",
		Keywords:  []string{"ACME_"},
		Regex:     `ACME_[A-Z0-9]{20}`,
		VerifyURL: srv.URL,
		VerifyHdr: "Authorization: Bearer {{ .Secret }}",
	})
	res, err := d.FromData(context.Background(), true, []byte("ACME_QWERTYUIOPASDFGHJKLZ"))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(res) != 1 || !res[0].Verified {
		t.Fatalf("expected one verified result; got %+v", res)
	}
}

func TestVerify_401IsUnverifiedNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()

	d, _ := Compile(Rule{
		Name:      "ACME Verify",
		Keywords:  []string{"ACME_"},
		Regex:     `ACME_[A-Z0-9]{20}`,
		VerifyURL: srv.URL,
	})
	res, err := d.FromData(context.Background(), true, []byte("ACME_QWERTYUIOPASDFGHJKLZ"))
	if err != nil {
		t.Fatalf("FromData: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d results", len(res))
	}
	if res[0].Verified {
		t.Errorf("expected Verified=false on 401")
	}
	if res[0].VerificationErr != nil {
		t.Errorf("401 should not surface as error; got %v", res[0].VerificationErr)
	}
}

func TestLoad_ParsesMultipleRules(t *testing.T) {
	doc := `[
		{"name":"r1","keywords":["x"],"regex":"x","severity":"low"},
		{"name":"r2","keywords":["y"],"regex":"y[0-9]+","severity":"critical"}
	]`
	rules, err := Load(strings.NewReader(doc))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules; got %d", len(rules))
	}
	if rules[0].severity != detectors.SeverityLow || rules[1].severity != detectors.SeverityCritical {
		t.Errorf("severity parse failed")
	}
}

func TestLoad_RejectsInvalidRule(t *testing.T) {
	doc := `[
		{"name":"r1","keywords":["x"],"regex":"x"},
		{"name":"r2","keywords":[],"regex":"y"}
	]`
	_, err := Load(strings.NewReader(doc))
	if err == nil || !strings.Contains(err.Error(), "rule[1]") {
		t.Fatalf("expected error pointing at rule[1]; got %v", err)
	}
}
