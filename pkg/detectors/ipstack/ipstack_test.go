//go:build detector_unit

package ipstack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/internal/redactiontest"
)

var dummy = strings.Repeat("0a", 16)

func withServer(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
}

func TestProviderConfirmedAssurance(t *testing.T) {
	var d detectors.Detector = Scanner{}
	p, ok := d.(detectors.VerificationPolicy)
	if !ok || p.MaxVerificationAssurance() != detectors.AssuranceProviderConfirmed {
		t.Fatal("ipstack must declare provider-confirmed assurance so --verify-min-assurance provider-confirmed verifies it")
	}
}

func TestFromData(t *testing.T) {
	in := []byte("ipstack key: " + dummy)
	res, err := redactiontest.FromData(t, Scanner{}, context.Background(), false, in)
	if err != nil || len(res) != 1 || string(res[0].Raw) != dummy {
		t.Fatalf("res=%v err=%v", res, err)
	}
	for _, in := range []string{dummy + " ipstack", "ipstack" + strings.Repeat("x", 41) + dummy, "ipstack=" + strings.Repeat("g", 32)} {
		if res, _ := redactiontest.FromData(t, Scanner{}, context.Background(), false, []byte(in)); len(res) != 0 {
			t.Fatalf("%q: expected 0, got %d", in, len(res))
		}
	}
}

func TestFromData_VerifyRuns(t *testing.T) {
	withServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/check" || r.URL.Query().Get("access_key") != dummy {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ip":"[PII:IP_ADDRESS]"}`))
	})
	res, err := redactiontest.FromData(t, Scanner{}, context.Background(), true, []byte("ipstack: "+dummy))
	if err != nil || len(res) != 1 || !res[0].Verified {
		t.Fatalf("res=%v err=%v", res, err)
	}
}

func TestVerify(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		want    bool
		wantErr bool
	}{
		{"lookup", 200, `{"ip":"[PII:IP_ADDRESS]"}`, true, false},
		{"invalid key", 200, `{"success":false,"error":{"code":101}}`, false, false},
		{"inactive", 200, `{"success":false,"error":{"code":102}}`, false, false},
		{"usage limit", 200, `{"success":false,"error":{"code":104}}`, true, false},
		{"https restricted", 200, `{"success":false,"error":{"code":105}}`, true, false},
		{"unknown code", 200, `{"success":false,"error":{"code":999}}`, false, true},
		{"missing ip", 200, `{}`, false, true},
		{"malformed", 200, `not-json`, false, true},
		{"server error", 503, ``, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			got, err := Scanner{}.Verify(context.Background(), dummy)
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Fatalf("got=(%v,%v) want=(%v,err=%v)", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func TestVerify_TransportErrorOmitsKey(t *testing.T) {
	old := apiBase
	apiBase = "http://[PII:IP_ADDRESS]:1"
	defer func() { apiBase = old }()
	_, err := Scanner{}.Verify(context.Background(), dummy)
	if err == nil || strings.Contains(err.Error(), dummy) {
		t.Fatalf("err=%v", err)
	}
}
