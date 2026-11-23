package tokenverify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/internal/redactiontest"
)

func TestClassify(t *testing.T) {
	valid := []Rule{{Status: 200, BodyContains: "ok"}, {Status: 403, BodyNotContains: "revoked"}}
	invalid := []Rule{{Status: 401}, {Status: 403}}
	for _, tc := range []struct {
		status  int
		body    string
		want    bool
		wantErr bool
	}{
		{200, `{"ok":1}`, true, false},
		{200, `{}`, false, true}, // 200 without the marker is ambiguous, never a negative
		{403, "scope missing", true, false},
		{403, "key revoked", false, false},
		{401, "", false, false},
		{429, "", false, true},
		{502, "", false, true},
		{418, "", false, true},
	} {
		got, err := classify("X", tc.status, []byte(tc.body), valid, invalid)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("%d %q: got %v, %v", tc.status, tc.body, got, err)
		}
	}
}

func TestFirstParticipatingGroupAndValidate(t *testing.T) {
	s := New(Spec{
		Type:     detectors.Apify,
		Keywords: []string{"x"},
		Pattern:  `(?:a_([0-9]{4})|b_([0-9]{4}))`,
		Validate: func(v string) bool { return v != "0000" },
	})
	res, err := redactiontest.FromData(t, s, context.Background(), false, []byte("b_1234 a_5678 a_5678 b_0000"))
	if err != nil || len(res) != 2 || string(res[0].Raw) != "1234" || string(res[1].Raw) != "5678" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if res[0].Redacted != "12..." {
		t.Fatalf("redacted %q", res[0].Redacted)
	}
}

func TestAuthPlacement(t *testing.T) {
	cases := map[string]struct {
		auth  Auth
		check func(*http.Request) bool
	}{
		"bearer": {Bearer(), func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer s3" }},
		"query":  {Query("k"), func(r *http.Request) bool { return r.URL.Query().Get("k") == "s3" && r.URL.Query().Get("keep") == "1" }},
		"basicU": {BasicUser(), func(r *http.Request) bool { u, p, ok := r.BasicAuth(); return ok && u == "s3" && p == "" }},
		"basicP": {BasicPassword("api"), func(r *http.Request) bool { u, p, ok := r.BasicAuth(); return ok && u == "api" && p == "s3" }},
		"basicR": {BasicRaw(), func(r *http.Request) bool { return r.Header.Get("Authorization") == "Basic czM=" }},
		"path":   {PathSecret(), func(r *http.Request) bool { return r.URL.Path == "/p/s3/x" }},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !tc.check(r) {
					t.Errorf("auth not placed: %s %v", r.URL, r.Header)
				}
				if r.Header.Get("X-Fixed") != "v" || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("headers not applied")
				}
			}))
			defer srv.Close()
			path := "/p?keep=1"
			if name == "path" {
				path = "/p/{secret}/x"
			}
			s := New(Spec{Type: detectors.Apify, Keywords: []string{"x"}, Pattern: `(x)`, Verify: Request{
				BaseURL: srv.URL, Path: path, Auth: tc.auth, Headers: map[string]string{"X-Fixed": "v"}, ContentType: "application/json",
			}})
			if ok, err := s.Verify(context.Background(), "s3"); !ok || err != nil {
				t.Fatalf("ok=%v err=%v", ok, err)
			}
		})
	}
}

func TestDefaultsAndPolicy(t *testing.T) {
	s := New(Spec{Type: detectors.Apify, Keywords: []string{"x"}, Pattern: `(x)`})
	if s.MaxVerificationAssurance() != detectors.AssuranceProviderConfirmed || s.VerificationCacheUsesFullInput() {
		t.Fatal("policy defaults")
	}
	if ok, err := s.Verify(context.Background(), ""); ok || err != nil {
		t.Fatal("empty secret must be a clean negative")
	}
}
