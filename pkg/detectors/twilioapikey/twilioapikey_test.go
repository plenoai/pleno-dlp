//go:build detector_unit

package twilioapikey

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/internal/redactiontest"
)

// Fixtures are assembled at runtime so push protection does not treat
// them as leaked keys.
var (
	hex32  = strings.Repeat("0123456789abcdef", 2)
	sid    = "SK" + hex32
	secret = strings.Repeat("aB3dE5fG", 4)
	acct   = "AC" + hex32
)

func withServer(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
}

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.TwilioAPIKey || detectors.TwilioAPIKey.String() != "TwilioAPIKey" {
		t.Fatal("type mismatch")
	}
}

func TestFromData_PairsSecret(t *testing.T) {
	body := []byte("TWILIO_API_KEY=" + sid + "\nTWILIO_API_SECRET=" + secret + "\n")
	res, _ := redactiontest.FromData(t, Scanner{}, context.Background(), false, body)
	if len(res) != 1 || string(res[0].Raw) != sid || string(res[0].RawV2) != secret {
		t.Fatalf("got %+v", res)
	}
}

func TestFromData_SIDOnly(t *testing.T) {
	res, _ := redactiontest.FromData(t, Scanner{}, context.Background(), false, []byte("key: "+sid))
	if len(res) != 1 || len(res[0].RawV2) != 0 {
		t.Fatalf("got %+v", res)
	}
}

func TestFromData_NoMatch(t *testing.T) {
	for _, in := range []string{"SKIP this", "SK0123", "x" + sid + "x"} {
		res, _ := redactiontest.FromData(t, Scanner{}, context.Background(), false, []byte(in))
		if len(res) != 0 {
			t.Fatalf("%q: got %+v", in, res)
		}
	}
}

func TestVerify(t *testing.T) {
	for _, tc := range []struct {
		status  int
		want    bool
		wantErr bool
	}{{200, true, false}, {401, false, false}, {403, false, false}, {500, false, true}, {429, false, true}} {
		withServer(t, func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if !ok || u != sid || p != secret || r.URL.Path != "/2010-04-01/Accounts.json" {
				t.Errorf("bad request %s %v", r.URL.Path, ok)
			}
			w.WriteHeader(tc.status)
		})
		got, err := Scanner{}.Verify(context.Background(), sid+":"+secret)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Fatalf("status %d: got %v err=%v", tc.status, got, err)
		}
	}
	if ok, err := (Scanner{}).Verify(context.Background(), sid); ok || err != nil {
		t.Fatal("unpaired secret must be a clean negative")
	}
}

func TestRevoke(t *testing.T) {
	t.Setenv(EnvRevokeAccountSID, acct)
	t.Setenv(EnvRevokeAuthToken, "tok")
	for _, tc := range []struct {
		status      int
		wantRevoked bool
		wantErr     bool
		wantDiag    bool
	}{{204, true, false, false}, {404, false, false, true}, {401, false, true, false}, {500, false, true, false}} {
		withServer(t, func(w http.ResponseWriter, r *http.Request) {
			u, p, _ := r.BasicAuth()
			if r.Method != http.MethodDelete || u != acct || p != "tok" || r.URL.Path != "/2010-04-01/Accounts/"+acct+"/Keys/"+sid+".json" {
				t.Errorf("bad request %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(tc.status)
		})
		res, err := Scanner{}.Revoke(context.Background(), sid+":"+secret)
		if res.Revoked != tc.wantRevoked || (err != nil) != tc.wantErr || (res.Err != nil) != tc.wantDiag {
			t.Fatalf("status %d: res=%+v err=%v", tc.status, res, err)
		}
		if tc.wantRevoked && res.ProviderID != sid {
			t.Fatalf("provider id = %q", res.ProviderID)
		}
	}
}

func TestRevoke_RequiresContext(t *testing.T) {
	t.Setenv(EnvRevokeAccountSID, "")
	t.Setenv(EnvRevokeAuthToken, "")
	if _, err := (Scanner{}).Revoke(context.Background(), sid); err == nil {
		t.Fatal("expected missing-context error")
	}
	t.Setenv(EnvRevokeAccountSID, "not-an-ac")
	t.Setenv(EnvRevokeAuthToken, "tok")
	if _, err := (Scanner{}).Revoke(context.Background(), sid); err == nil {
		t.Fatal("expected invalid account SID error")
	}
	if _, err := (Scanner{}).Revoke(context.Background(), "AC0123"); err == nil {
		t.Fatal("expected invalid key SID error")
	}
}
