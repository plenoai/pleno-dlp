package aws

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// AKIAIOSFODNN7EXAMPLE is AWS's documentation example access key id.
// It has the canonical AKIA prefix + 16 uppercase alphanumerics.
const dummyAccessKeyID = "AKIAIOSFODNN7EXAMPLE"

const (
	testAdminAccessKeyID     = "AKIAIOSFODNN7ADMIN00"
	testAdminSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	testUserName             = "alice"
)

// revokeServer asserts the request shape (method, body fields, SigV4
// auth header) matches the documented contract and serves the
// requested status with the requested body.
func revokeServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("revoke: expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/" {
			t.Errorf("revoke: path = %q, want /", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
			t.Errorf("revoke: missing AWS4-HMAC-SHA256 auth header (%q)", auth)
		}
		if !strings.Contains(auth, "Credential="+testAdminAccessKeyID+"/") {
			t.Errorf("revoke: auth header missing admin access key id: %q", auth)
		}
		if !strings.Contains(auth, "SignedHeaders=") {
			t.Errorf("revoke: auth header missing SignedHeaders: %q", auth)
		}
		if !strings.Contains(auth, "Signature=") {
			t.Errorf("revoke: auth header missing Signature: %q", auth)
		}
		if r.Header.Get("X-Amz-Date") == "" {
			t.Error("revoke: missing X-Amz-Date header")
		}
		raw, _ := io.ReadAll(r.Body)
		form, err := url.ParseQuery(string(raw))
		if err != nil {
			t.Errorf("revoke: bad body form: %v (raw=%q)", err, string(raw))
		}
		if form.Get("Action") != "DeleteAccessKey" {
			t.Errorf("revoke: Action = %q, want DeleteAccessKey", form.Get("Action"))
		}
		if form.Get("AccessKeyId") != dummyAccessKeyID {
			t.Errorf("revoke: AccessKeyId = %q, want %q", form.Get("AccessKeyId"), dummyAccessKeyID)
		}
		if form.Get("UserName") != testUserName {
			t.Errorf("revoke: UserName = %q, want %q", form.Get("UserName"), testUserName)
		}
		if form.Get("Version") != "2010-05-08" {
			t.Errorf("revoke: Version = %q, want 2010-05-08", form.Get("Version"))
		}
		w.WriteHeader(status)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func withRevokeServer(t *testing.T, status int, body string) *httptest.Server {
	srv := revokeServer(t, status, body)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	SetRevokeCredentials(testAdminAccessKeyID, testAdminSecretAccessKey, "", "us-east-1", testUserName)
	t.Cleanup(func() { SetRevokeCredentials("", "", "", "", "") })
	return srv
}

const successBody = `<?xml version="1.0"?><DeleteAccessKeyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata></DeleteAccessKeyResponse>`

const noSuchEntityBody = `<?xml version="1.0"?><ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type><Code>NoSuchEntity</Code><Message>The Access Key with id ` + dummyAccessKeyID + ` cannot be found.</Message></Error><RequestId>req-2</RequestId></ErrorResponse>`

const accessDeniedBody = `<?xml version="1.0"?><ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>User: arn:aws:iam::1:user/x is not authorized to perform: iam:DeleteAccessKey</Message></Error><RequestId>req-3</RequestId></ErrorResponse>`

const throttlingBody = `<?xml version="1.0"?><ErrorResponse><Error><Type>Sender</Type><Code>Throttling</Code><Message>Rate exceeded</Message></Error><RequestId>req-4</RequestId></ErrorResponse>`

func TestRevoke_Success(t *testing.T) {
	withRevokeServer(t, http.StatusOK, successBody)

	res, err := Scanner{}.Revoke(context.Background(), dummyAccessKeyID)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatal("expected Revoked=true on 200")
	}
	if res.ProviderID != dummyAccessKeyID {
		t.Errorf("ProviderID = %q, want %q", res.ProviderID, dummyAccessKeyID)
	}
	if res.RevokedAt.IsZero() {
		t.Error("RevokedAt unset on success")
	}
}

func TestRevoke_Idempotent_NoSuchEntity(t *testing.T) {
	// IAM returns 404 for NoSuchEntity. Our parser drives off the body
	// Code element so the http status does not matter for routing.
	withRevokeServer(t, http.StatusNotFound, noSuchEntityBody)

	res, err := Scanner{}.Revoke(context.Background(), dummyAccessKeyID)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatal("expected Revoked=true on NoSuchEntity (idempotency)")
	}
	if res.Err == nil {
		t.Fatal("expected non-nil Err diagnostic on NoSuchEntity")
	}
}

func TestRevoke_AccessDenied(t *testing.T) {
	withRevokeServer(t, http.StatusForbidden, accessDeniedBody)

	_, err := Scanner{}.Revoke(context.Background(), dummyAccessKeyID)
	if err == nil {
		t.Fatal("expected hard error on AccessDenied")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("error must mention AccessDenied: %v", err)
	}
}

func TestRevoke_NonAccessKeyInput(t *testing.T) {
	SetRevokeCredentials(testAdminAccessKeyID, testAdminSecretAccessKey, "", "us-east-1", testUserName)
	t.Cleanup(func() { SetRevokeCredentials("", "", "", "", "") })

	for _, in := range []string{
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // secret access key (40 chars, not AKIA)
		"ASIAIOSFODNN7EXAMPLE",                     // session/temp key
		"AKIAEXAMPLE",                              // too short
		"akiaiosfodnn7example",                     // wrong case
		"AKIAIOSFODNN7EXAMPL!",                     // bad final char
		"AKIA" + strings.Repeat("0", 17),           // too long
	} {
		_, err := Scanner{}.Revoke(context.Background(), in)
		if err == nil {
			t.Errorf("expected error for non-AKIA input %q", in)
			continue
		}
		if !strings.Contains(err.Error(), "Access Key ID") {
			t.Errorf("error must mention Access Key ID for input %q: %v", in, err)
		}
	}
}

func TestRevoke_MissingCreds(t *testing.T) {
	SetRevokeCredentials("", "", "", "", "")
	t.Setenv(EnvAdminAccessKeyID, "")
	t.Setenv(EnvAdminSecretAccessKey, "")
	t.Setenv(EnvAdminSessionToken, "")
	t.Setenv(EnvRegion, "")
	t.Setenv(EnvUserName, "")

	_, err := Scanner{}.Revoke(context.Background(), dummyAccessKeyID)
	if err == nil {
		t.Fatal("expected error when admin creds / user name unset")
	}
	for _, want := range []string{EnvAdminAccessKeyID, EnvAdminSecretAccessKey, EnvUserName} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error message should reference %s, got %v", want, err)
		}
	}
}

func TestRevoke_MissingUserName(t *testing.T) {
	SetRevokeCredentials(testAdminAccessKeyID, testAdminSecretAccessKey, "", "us-east-1", "")
	t.Cleanup(func() { SetRevokeCredentials("", "", "", "", "") })
	t.Setenv(EnvUserName, "")

	_, err := Scanner{}.Revoke(context.Background(), dummyAccessKeyID)
	if err == nil {
		t.Fatal("expected error when user name unset (creds present)")
	}
	if !strings.Contains(err.Error(), EnvUserName) {
		t.Errorf("error should reference %s: %v", EnvUserName, err)
	}
}

func TestRevoke_RateLimited_Throttling(t *testing.T) {
	withRevokeServer(t, http.StatusBadRequest, throttlingBody)

	_, err := Scanner{}.Revoke(context.Background(), dummyAccessKeyID)
	if err == nil {
		t.Fatal("Throttling must surface as hard error")
	}
	if !strings.Contains(err.Error(), "rate-limit") && !strings.Contains(err.Error(), "Throttling") {
		t.Errorf("error must mention rate-limit / Throttling: %v", err)
	}
}

func TestRevoke_RateLimited_429(t *testing.T) {
	// Bare 429 with no XML body — defensive path for atypical proxies.
	withRevokeServer(t, http.StatusTooManyRequests, "")

	_, err := Scanner{}.Revoke(context.Background(), dummyAccessKeyID)
	if err == nil {
		t.Fatal("429 must surface as hard error")
	}
	if !strings.Contains(err.Error(), "429") {
		t.Errorf("error must mention 429: %v", err)
	}
}

func TestRevoke_NetworkError(t *testing.T) {
	prev := apiBase
	apiBase = "http://127.0.0.1:1" // refused
	t.Cleanup(func() { apiBase = prev })
	SetRevokeCredentials(testAdminAccessKeyID, testAdminSecretAccessKey, "", "us-east-1", testUserName)
	t.Cleanup(func() { SetRevokeCredentials("", "", "", "", "") })

	got, err := Scanner{}.Revoke(context.Background(), dummyAccessKeyID)
	if err == nil {
		t.Fatal("network failure must surface via the second return value")
	}
	if got.Revoked {
		t.Error("must not report Revoked=true on transport failure")
	}
	if got.Err != nil {
		t.Errorf("transport failures must not populate RevokeResult.Err: %v", got.Err)
	}
}

func TestRevoke_EmptySecret(t *testing.T) {
	SetRevokeCredentials(testAdminAccessKeyID, testAdminSecretAccessKey, "", "us-east-1", testUserName)
	t.Cleanup(func() { SetRevokeCredentials("", "", "", "", "") })

	_, err := Scanner{}.Revoke(context.Background(), "")
	if err == nil {
		t.Fatal("expected error on empty secret")
	}
}

func TestRevoke_EnvFallback(t *testing.T) {
	t.Setenv(EnvAdminAccessKeyID, testAdminAccessKeyID)
	t.Setenv(EnvAdminSecretAccessKey, testAdminSecretAccessKey)
	t.Setenv(EnvUserName, testUserName)
	srv := revokeServer(t, http.StatusOK, successBody)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	// Make sure programmatic creds are empty so env-fallback fires.
	SetRevokeCredentials("", "", "", "", "")

	res, err := Scanner{}.Revoke(context.Background(), dummyAccessKeyID)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatal("expected env-fallback Revoke to succeed on 200")
	}
}

func TestRevoke_SessionTokenSigned(t *testing.T) {
	// When a session token is supplied (e.g. assume-role admin), it MUST
	// be sent as X-Amz-Security-Token AND included in SignedHeaders.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Amz-Security-Token"); got != "FAKE-SESSION-TOKEN" {
			t.Errorf("X-Amz-Security-Token = %q, want FAKE-SESSION-TOKEN", got)
		}
		auth := r.Header.Get("Authorization")
		if !strings.Contains(auth, "x-amz-security-token") {
			t.Errorf("auth must include x-amz-security-token in SignedHeaders: %q", auth)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(successBody))
	}))
	t.Cleanup(srv.Close)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() { apiBase = old })
	SetRevokeCredentials(testAdminAccessKeyID, testAdminSecretAccessKey, "FAKE-SESSION-TOKEN", "us-east-1", testUserName)
	t.Cleanup(func() { SetRevokeCredentials("", "", "", "", "") })

	res, err := Scanner{}.Revoke(context.Background(), dummyAccessKeyID)
	if err != nil {
		t.Fatalf("Revoke err: %v", err)
	}
	if !res.Revoked {
		t.Fatal("expected Revoked=true with session token")
	}
}

func TestRevoke_InterfaceSatisfied(t *testing.T) {
	// Compile-time check is in revoke.go; runtime check guards against
	// a future change that drops the interface implementation without
	// touching the assertion.
	var _ detectors.Revoker = Scanner{}
}

func TestExtractErrorCode(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{noSuchEntityBody, "NoSuchEntity"},
		{accessDeniedBody, "AccessDenied"},
		{successBody, ""},
		{"", ""},
		{"<Error><Code>Throttling</Code></Error>", "Throttling"},
		{"<Code></Code>", ""}, // empty value still yields empty string
		{"<Code>missing closing", ""},
	}
	for _, c := range cases {
		got := extractErrorCode([]byte(c.in))
		if got != c.want {
			t.Errorf("extractErrorCode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsAccessKeyID(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{dummyAccessKeyID, true},
		{"AKIAIOSFODNN7EXAMPL!", false},
		{"akiaiosfodnn7example", false},
		{"ASIAIOSFODNN7EXAMPLE", false}, // ASIA is temp credentials, out of scope
		{"AKIA", false},
		{"", false},
		{"AKIA" + strings.Repeat("0", 16), true},
		{"AKIA" + strings.Repeat("0", 17), false},
	}
	for _, c := range cases {
		if got := isAccessKeyID(c.in); got != c.want {
			t.Errorf("isAccessKeyID(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
