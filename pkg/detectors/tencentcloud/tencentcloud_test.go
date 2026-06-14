//go:build detector_unit

package tencentcloud

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyID = "AKIDabcdefghijklmnopqrstuvwxyz0123"
const dummySecret = "abcdefghijklmnopqrstuvwxyz012345"

func TestFromData_Pair(t *testing.T) {
	body := "tencent_secret_id=" + dummyID + "\ntencent_secret_key=" + dummySecret + "\n"
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyID {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("rawV2 mismatch: %q", res[0].RawV2)
	}
	if res[0].Severity != 5 {
		t.Fatalf("expected critical for paired creds, got %d", res[0].Severity)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("random "+dummyID+" word"))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "AKIDabcd") {
		t.Fatalf("missing prefix: %q", r)
	}
}

// withServer points apiBase at an httptest server for the duration of fn.
func withServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() {
		apiBase = old
		srv.Close()
	})
	return srv
}

func TestVerify_OK(t *testing.T) {
	withServer(t, func(w http.ResponseWriter, r *http.Request) {
		// TC3 signing assertions: the signed headers and credential scope must
		// be present so a signing regression is caught.
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "TC3-HMAC-SHA256 ") {
			t.Errorf("missing TC3 algorithm prefix: %q", auth)
		}
		if !strings.Contains(auth, "Credential="+dummyID+"/") {
			t.Errorf("credential scope missing SecretId: %q", auth)
		}
		if !strings.Contains(auth, "/sts/tc3_request") {
			t.Errorf("credential scope missing sts service: %q", auth)
		}
		if r.Header.Get("X-TC-Action") != stsAction {
			t.Errorf("X-TC-Action mismatch: %q", r.Header.Get("X-TC-Action"))
		}
		// HTTP 200 with identity body == valid.
		_, _ = w.Write([]byte(`{"Response":{"AccountId":"100000000001","Arn":"qcs::cam::uin/100000000001:uin/100000000001","RequestId":"req-1"}}`))
	})

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err != nil {
		t.Fatalf("Verify err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_AuthFailureOn200(t *testing.T) {
	// TencentCloud returns HTTP 200 even for revoked/invalid keys, encoding the
	// failure in the body. This must NOT be a false verified=true.
	withServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Response":{"Error":{"Code":"AuthFailure.SignatureFailure","Message":"signature mismatch"},"RequestId":"req-2"}}`))
	})

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err != nil {
		t.Fatalf("err must be nil for authoritative AuthFailure: %v", err)
	}
	if v {
		t.Fatal("AuthFailure body on HTTP 200 must yield verified=false")
	}
}

func TestVerify_SecretIdNotFoundOn200(t *testing.T) {
	withServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Response":{"Error":{"Code":"AuthFailure.SecretIdNotFound","Message":"no such id"},"RequestId":"req-3"}}`))
	})

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_Transient500(t *testing.T) {
	withServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err == nil {
		t.Fatal("expected transient error on HTTP 500")
	}
	if v {
		t.Fatal("verified must be false on transient error")
	}
}

func TestVerify_Transient429(t *testing.T) {
	withServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})

	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err == nil {
		t.Fatal("expected transient error on HTTP 429")
	}
	if v {
		t.Fatal("verified must be false on 429")
	}
}

func TestVerify_UnpairedIsNoop(t *testing.T) {
	// A lone SecretId (no ':') is not a credential — verify must be a no-op and
	// must not attempt any HTTP call.
	called := false
	withServer(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	v, err := Scanner{}.Verify(context.Background(), dummyID)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if v {
		t.Fatal("unpaired SecretId must not verify")
	}
	if called {
		t.Fatal("unpaired verify must not issue an HTTP request")
	}
}

func TestFromData_VerifySetsAccountID(t *testing.T) {
	withServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Response":{"AccountId":"100000000099","Arn":"qcs::cam::uin/100000000099:root","RequestId":"req-4"}}`))
	})

	body := "tencent_secret_id=" + dummyID + "\ntencent_secret_key=" + dummySecret + "\n"
	res, _ := Scanner{}.FromData(context.Background(), true, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatal("expected Verified=true")
	}
	if res[0].VerificationErr != nil {
		t.Fatalf("unexpected VerificationErr: %v", res[0].VerificationErr)
	}
	if res[0].ExtraData["tencent_account_id"] != "100000000099" {
		t.Fatalf("account id not set: %q", res[0].ExtraData["tencent_account_id"])
	}
}

func TestFromData_VerifyAuthFailureNotVerified(t *testing.T) {
	withServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Response":{"Error":{"Code":"AuthFailure.TokenFailure","Message":"bad"},"RequestId":"req-5"}}`))
	})

	body := "tencent_secret_id=" + dummyID + "\ntencent_secret_key=" + dummySecret + "\n"
	res, _ := Scanner{}.FromData(context.Background(), true, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if res[0].Verified {
		t.Fatal("AuthFailure must leave Verified=false")
	}
	if res[0].VerificationErr != nil {
		t.Fatalf("authoritative AuthFailure must not set VerificationErr: %v", res[0].VerificationErr)
	}
}
