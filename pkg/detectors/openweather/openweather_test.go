//go:build detector_unit

package openweather

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
		t.Fatal("openweather must declare provider-confirmed assurance so --verify-min-assurance provider-confirmed verifies it")
	}
}

func TestFromData(t *testing.T) {
	in := []byte("openweather key: " + dummy)
	res, err := redactiontest.FromData(t, Scanner{}, context.Background(), false, in)
	if err != nil || len(res) != 1 || string(res[0].Raw) != dummy {
		t.Fatalf("res=%v err=%v", res, err)
	}
	for _, in := range []string{dummy + " openweather", "openweather" + strings.Repeat("x", 41) + dummy, "openweather=" + strings.Repeat("g", 32)} {
		if res, _ := redactiontest.FromData(t, Scanner{}, context.Background(), false, []byte(in)); len(res) != 0 {
			t.Fatalf("%q: expected 0, got %d", in, len(res))
		}
	}
}

func TestFromData_VerifyRuns(t *testing.T) {
	withServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/data/2.5/weather" || r.URL.Query().Get("appid") != dummy {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"ip":"[PII:IP_ADDRESS]"}`))
	})
	res, err := redactiontest.FromData(t, Scanner{}, context.Background(), true, []byte("openweather: "+dummy))
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
		{"valid", 200, `{"cod":200}`, true, false},
		{"invalid key", 401, `{"cod":401}`, false, false},
		{"rate limited", 429, ``, false, true},
		{"ambiguous", 404, ``, false, true},
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
