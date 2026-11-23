// Package tokenverifytest is the shared contract test for tokenverify
// specs: detection through the redaction harness, the exact verification
// request shape, and the valid / invalid / transient / ambiguous verdicts.
package tokenverifytest

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/internal/redactiontest"
	"github.com/plenoai/pleno-dlp/pkg/detectors/tokenverify"
)

// Case is one detector's fixture.
type Case struct {
	// Input contains exactly one secret, Want.
	Input string
	Want  string
	// Negatives must produce no finding.
	Negatives []string
}

// Check runs the full contract for s.
func Check(t *testing.T, s *tokenverify.Scanner, c Case) {
	t.Helper()
	spec := s.Spec()
	if spec.Type.String() == "Unknown" {
		t.Fatalf("detector type %d has no String() name", spec.Type)
	}
	if len(spec.Keywords) == 0 {
		t.Fatal("keywords empty")
	}
	lower := strings.ToLower(c.Input)
	hasKW := false
	for _, kw := range spec.Keywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			hasKW = true
		}
	}
	if !hasKW {
		t.Fatalf("input %q contains none of the keywords %v; the engine would never dispatch it", c.Input, spec.Keywords)
	}

	res, _ := redactiontest.FromData(t, s, context.Background(), false, []byte(c.Input))
	if len(res) != 1 || string(res[0].Raw) != c.Want {
		t.Fatalf("FromData(%q) = %+v, want one result %q", c.Input, res, c.Want)
	}
	if res[0].DetectorType != spec.Type {
		t.Fatalf("result type %v, want %v", res[0].DetectorType, spec.Type)
	}
	for _, neg := range c.Negatives {
		if got, _ := redactiontest.FromData(t, s, context.Background(), false, []byte(neg)); len(got) != 0 {
			t.Fatalf("negative %q produced %+v", neg, got)
		}
	}

	v := spec.Verify
	valid, invalid := v.Valid[0], v.Invalid[0]
	respond := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Method != v.Method {
				t.Errorf("method %s, want %s", r.Method, v.Method)
			}
			if !carriesSecret(r, c.Want) {
				t.Errorf("verification request does not carry the secret (path %s)", r.URL.Path)
			}
			if v.Body != "" {
				b, _ := io.ReadAll(r.Body)
				if string(b) != v.Body {
					t.Errorf("body %q, want %q", b, v.Body)
				}
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	statusOr := func(s, d int) int {
		if s == 0 {
			return d
		}
		return s
	}
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		want    bool
		wantErr bool
	}{
		{"valid", statusOr(valid.Status, 200), valid.BodyContains, true, false},
		{"invalid", statusOr(invalid.Status, 401), invalid.BodyContains, false, false},
		{"transient", 503, "", false, true},
		{"rate-limited", 429, "", false, true},
		{"ambiguous", 418, "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(respond(tc.status, tc.body))
			defer srv.Close()
			defer s.SetBaseURL(srv.URL)()
			got, err := s.Verify(context.Background(), c.Want)
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("Verify = %v, %v; want %v, err=%v", got, err, tc.want, tc.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), c.Want) {
				t.Fatalf("error leaks the secret: %v", err)
			}
		})
	}
	if _, ok := any(s).(detectors.Verifier); !ok {
		t.Fatal("not a Verifier")
	}
}

func carriesSecret(r *http.Request, secret string) bool {
	if strings.Contains(r.URL.Path, secret) || strings.Contains(r.URL.RawQuery, secret) {
		return true
	}
	for _, vals := range r.Header {
		for _, v := range vals {
			if strings.Contains(v, secret) {
				return true
			}
			if raw, ok := strings.CutPrefix(v, "Basic "); ok {
				if dec, err := base64.StdEncoding.DecodeString(raw); err == nil && strings.Contains(string(dec), secret) {
					return true
				}
			}
		}
	}
	if q := r.URL.Query(); q != nil {
		for _, vals := range q {
			for _, v := range vals {
				if v == secret {
					return true
				}
			}
		}
	}
	return false
}
