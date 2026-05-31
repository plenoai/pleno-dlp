package connectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// verifyStatusServer spins up an httptest server that always replies with the
// given status code and body, and returns its URL. The body lets Slack's
// body-driven verify path be exercised alongside the status-driven ones.
func verifyStatusServer(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// statusVerifyCase models one row of a status-driven verify func's contract:
// the HTTP status the provider returns, and the (ok, wantErr) the verify func
// must map it to.
type statusVerifyCase struct {
	name    string
	status  int
	wantOK  bool
	wantErr bool
}

// runStatusVerify drives a verify func against an httptest server for each case
// and asserts the (ok, err) mapping. cfgFor builds the Config (so each
// connector can inject api_base/email exactly as its verify func reads it).
func runStatusVerify(t *testing.T, verify Verify, cfgFor func(base string) Config, cases []statusVerifyCase) {
	t.Helper()
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			base := verifyStatusServer(t, tc.status, `{"ok":false}`)
			ok, err := verify(context.Background(), cfgFor(base), "secret-token")
			if (err != nil) != tc.wantErr {
				t.Fatalf("status %d: err = %v, wantErr = %v", tc.status, err, tc.wantErr)
			}
			if ok != tc.wantOK {
				t.Fatalf("status %d: ok = %v, want %v", tc.status, ok, tc.wantOK)
			}
		})
	}
}

// --- GitHub: 200 -> true; 401/403 -> false,nil; 5xx/default -> false,err ---

func TestVerifyGitHub(t *testing.T) {
	cfg := func(base string) Config { return Config{"api_base": base} }
	runStatusVerify(t, verifyGitHub, cfg, []statusVerifyCase{
		{"ok200", http.StatusOK, true, false},
		{"unauthorized401", http.StatusUnauthorized, false, false},
		{"forbidden403", http.StatusForbidden, false, false},
		{"server500", http.StatusInternalServerError, false, true},
	})
}

// --- GitLab: 200 -> true; 401/403 -> false,nil; 5xx/default -> false,err ---

func TestVerifyGitLab(t *testing.T) {
	cfg := func(base string) Config { return Config{"api_base": base} }
	runStatusVerify(t, verifyGitLab, cfg, []statusVerifyCase{
		{"ok200", http.StatusOK, true, false},
		{"unauthorized401", http.StatusUnauthorized, false, false},
		{"forbidden403", http.StatusForbidden, false, false},
		{"server500", http.StatusInternalServerError, false, true},
	})
}

// --- Bitbucket: 200 -> true; 401 -> false,nil; everything else (incl 403)
// -> false,err. The 403 case is deliberately mapped to error, mirroring the
// connector's switch which only special-cases StatusUnauthorized. The server
// must serve the full /2.0/user path the verify func requests.

func TestVerifyBitbucket(t *testing.T) {
	cfg := func(base string) Config { return Config{"api_base": base} }
	runStatusVerify(t, verifyBitbucket, cfg, []statusVerifyCase{
		{"ok200", http.StatusOK, true, false},
		{"unauthorized401", http.StatusUnauthorized, false, false},
		{"forbidden403_is_error", http.StatusForbidden, false, true},
		{"server500", http.StatusInternalServerError, false, true},
	})
}

// --- Confluence: 200 -> true; 401/403 -> false,nil; 5xx/default -> false,err.
// api_base is required; the verify func reads cfg["email"]="" -> Bearer.

func TestVerifyConfluence(t *testing.T) {
	cfg := func(base string) Config { return Config{"api_base": base} }
	runStatusVerify(t, verifyConfluence, cfg, []statusVerifyCase{
		{"ok200", http.StatusOK, true, false},
		{"unauthorized401", http.StatusUnauthorized, false, false},
		{"forbidden403", http.StatusForbidden, false, false},
		{"server500", http.StatusInternalServerError, false, true},
	})
}

// TestVerifyConfluenceMissingAPIBase covers the required-config guard: no
// api_base means verify returns an error before any HTTP call.
func TestVerifyConfluenceMissingAPIBase(t *testing.T) {
	ok, err := verifyConfluence(context.Background(), Config{}, "secret")
	if err == nil {
		t.Fatal("verifyConfluence with no api_base: err = nil, want error")
	}
	if ok {
		t.Fatal("verifyConfluence with no api_base: ok = true, want false")
	}
}

// --- Jira: 200 -> true; 401/403 -> false,nil; 5xx/default -> false,err. ---

func TestVerifyJira(t *testing.T) {
	cfg := func(base string) Config { return Config{"api_base": base} }
	runStatusVerify(t, verifyJira, cfg, []statusVerifyCase{
		{"ok200", http.StatusOK, true, false},
		{"unauthorized401", http.StatusUnauthorized, false, false},
		{"forbidden403", http.StatusForbidden, false, false},
		{"server500", http.StatusInternalServerError, false, true},
	})
}

// TestVerifyJiraMissingAPIBase covers the required-config guard.
func TestVerifyJiraMissingAPIBase(t *testing.T) {
	ok, err := verifyJira(context.Background(), Config{}, "secret")
	if err == nil {
		t.Fatal("verifyJira with no api_base: err = nil, want error")
	}
	if ok {
		t.Fatal("verifyJira with no api_base: ok = true, want false")
	}
}

// --- Notion: 200 -> true; 401 -> false,nil; everything else (incl 403)
// -> false,err. Like Bitbucket, the switch only special-cases 401.

func TestVerifyNotion(t *testing.T) {
	cfg := func(base string) Config { return Config{"api_base": base} }
	runStatusVerify(t, verifyNotion, cfg, []statusVerifyCase{
		{"ok200", http.StatusOK, true, false},
		{"unauthorized401", http.StatusUnauthorized, false, false},
		{"forbidden403_is_error", http.StatusForbidden, false, true},
		{"server500", http.StatusInternalServerError, false, true},
	})
}

// --- Slack: body-driven. verifySlack calls do() (which does NOT inspect HTTP
// status) and decodes the JSON `ok` field. So the contract is:
//   - 200 {"ok":true}  -> true,nil   (alive)
//   - 401/403 {"ok":false} -> false,nil (auth failure, decodes fine, not an error)
//   - 5xx non-JSON body -> false,err  (decode failure surfaces as error)

func TestVerifySlack(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantOK  bool
		wantErr bool
	}{
		{"ok200", http.StatusOK, `{"ok":true}`, true, false},
		{"unauthorized401", http.StatusUnauthorized, `{"ok":false,"error":"invalid_auth"}`, false, false},
		{"forbidden403", http.StatusForbidden, `{"ok":false,"error":"account_inactive"}`, false, false},
		{"server500_nonjson", http.StatusInternalServerError, "boom", false, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			base := verifyStatusServer(t, tc.status, tc.body)
			ok, err := verifySlack(context.Background(), Config{"api_base": base}, "xoxb-secret")
			if (err != nil) != tc.wantErr {
				t.Fatalf("status %d body %q: err = %v, wantErr = %v", tc.status, tc.body, err, tc.wantErr)
			}
			if ok != tc.wantOK {
				t.Fatalf("status %d body %q: ok = %v, want %v", tc.status, tc.body, ok, tc.wantOK)
			}
		})
	}
}
