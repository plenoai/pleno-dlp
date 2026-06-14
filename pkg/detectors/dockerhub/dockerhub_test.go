//go:build detector_unit

package dockerhub

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

const dummy = "dckr_pat_AbCdEfGhIjKlMnOpQrStUvWx12"

func TestFromData_Positive(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("DOCKERHUB_TOKEN="+dummy))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummy {
		t.Fatalf("raw: %q", res[0].Raw)
	}
}

func TestFromData_WithUsername(t *testing.T) {
	body := "DOCKER_USERNAME=alice\nDOCKERHUB_TOKEN=" + dummy
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1")
	}
	if string(res[0].RawV2) != "alice" {
		t.Fatalf("rawv2: %q", res[0].RawV2)
	}
	if got := res[0].ExtraData["username"]; got != "alice" {
		t.Fatalf("username: %q", got)
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("password=hunter2"))
	if len(res) != 0 {
		t.Fatalf("expected 0")
	}
}

func setAPIBase(t *testing.T, url string) {
	t.Helper()
	old := apiBase
	apiBase = url
	t.Cleanup(func() { apiBase = old })
}

// tokenServer asserts the request shape (POST /v2/auth/token with a JSON
// {identifier,secret} body) and replies with the given status code.
func tokenServer(t *testing.T, code int, wantUser, wantToken string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v2/auth/token" {
			t.Errorf("path = %s, want /v2/auth/token", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var got map[string]string
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("body not json: %v (%q)", err, body)
		}
		if got["identifier"] != wantUser {
			t.Errorf("identifier = %q, want %q", got["identifier"], wantUser)
		}
		if got["secret"] != wantToken {
			t.Errorf("secret = %q, want %q", got["secret"], wantToken)
		}
		w.WriteHeader(code)
		if code == http.StatusOK {
			_, _ = w.Write([]byte(`{"token":"jwt.header.payload"}`))
		}
	}))
}

func TestVerify_OK(t *testing.T) {
	srv := tokenServer(t, http.StatusOK, "alice", dummy)
	defer srv.Close()
	setAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), "alice"+pairSep+dummy)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := tokenServer(t, http.StatusUnauthorized, "alice", dummy)
	defer srv.Close()
	setAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), "alice"+pairSep+dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 401")
	}
}

func TestVerify_TransientServerError(t *testing.T) {
	srv := tokenServer(t, http.StatusInternalServerError, "alice", dummy)
	defer srv.Close()
	setAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), "alice"+pairSep+dummy)
	if v {
		t.Fatal("500 must not verify")
	}
	if err == nil {
		t.Fatal("expected transient error on 500")
	}
}

func TestVerify_RateLimitTransient(t *testing.T) {
	srv := tokenServer(t, http.StatusTooManyRequests, "alice", dummy)
	defer srv.Close()
	setAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), "alice"+pairSep+dummy)
	if v {
		t.Fatal("429 must not verify")
	}
	if err == nil {
		t.Fatal("expected transient error on 429")
	}
}

func TestVerify_NoUsernameNoOps(t *testing.T) {
	// No server should be hit when there is no username.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("verify must not call the API without a username")
	}))
	defer srv.Close()
	setAPIBase(t, srv.URL)

	v, err := Scanner{}.Verify(context.Background(), dummy) // no separator → no username
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false when username absent")
	}
}

func TestFromData_VerifyPairOK(t *testing.T) {
	srv := tokenServer(t, http.StatusOK, "alice", dummy)
	defer srv.Close()
	setAPIBase(t, srv.URL)

	body := "DOCKER_USERNAME=alice\nDOCKERHUB_TOKEN=" + dummy
	res, err := Scanner{}.FromData(context.Background(), true, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatalf("expected Verified=true, err=%v", res[0].VerificationErr)
	}
}

func TestFromData_VerifyTokenOnlyNotVerified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("must not call API without a username")
	}))
	defer srv.Close()
	setAPIBase(t, srv.URL)

	res, _ := Scanner{}.FromData(context.Background(), true, []byte("DOCKERHUB_TOKEN="+dummy))
	if len(res) != 1 {
		t.Fatalf("expected 1")
	}
	if res[0].Verified {
		t.Fatal("token-only candidate must not be verified")
	}
}
