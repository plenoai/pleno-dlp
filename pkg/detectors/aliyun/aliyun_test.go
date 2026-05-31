package aliyun

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyID = "LTAIabcdef0123456789"
const dummySecret = "abcdefghijklmnopqrstuvwxyz0123"

func TestFromData_Pair(t *testing.T) {
	body := "aliyun_access_key_id=" + dummyID + "\naliyun_access_key_secret=" + dummySecret + "\n"
	res, err := Scanner{}.FromData(context.Background(), false, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(res))
	}
	if string(res[0].Raw) != dummyID {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("rawV2 mismatch: %q", res[0].RawV2)
	}
	if res[0].Severity != 5 { // SeverityCritical
		t.Fatalf("expected critical severity for paired creds, got %d", res[0].Severity)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	// LTAI alone with no aliyun/alibaba context keyword should be ignored.
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("random log line "+dummyID+" appears here"))
	if len(res) != 0 {
		t.Fatalf("expected 0 hits without context, got %d", len(res))
	}
}

func TestFromData_Negative(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("aliyun nothing here"))
	if len(res) != 0 {
		t.Fatalf("expected 0 hits, got %d", len(res))
	}
}

func withServer(t *testing.T, code int) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sanity: the probe must hit ECS DescribeRegions with a signature.
		q := r.URL.Query()
		if q.Get("Action") != "DescribeRegions" {
			t.Errorf("unexpected Action %q", q.Get("Action"))
		}
		if q.Get("Signature") == "" {
			t.Error("missing Signature in signed request")
		}
		if q.Get("AccessKeyId") != dummyID {
			t.Errorf("unexpected AccessKeyId %q", q.Get("AccessKeyId"))
		}
		w.WriteHeader(code)
	}))
	old := apiBase
	apiBase = srv.URL
	t.Cleanup(func() {
		apiBase = old
		srv.Close()
	})
}

func TestVerify_Accept200(t *testing.T) {
	withServer(t, http.StatusOK)
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true on 200")
	}
}

func TestVerify_Reject400(t *testing.T) {
	// 400 = SignatureDoesNotMatch / InvalidAccessKeyId — explicit rejection.
	withServer(t, http.StatusBadRequest)
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 400")
	}
}

func TestVerify_Reject404(t *testing.T) {
	withServer(t, http.StatusNotFound)
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false on 404")
	}
}

func TestVerify_Transient500(t *testing.T) {
	withServer(t, http.StatusInternalServerError)
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err == nil {
		t.Fatal("expected transient error on 500")
	}
	if v {
		t.Fatal("expected verified=false on 500")
	}
}

func TestVerify_Transient429(t *testing.T) {
	withServer(t, http.StatusTooManyRequests)
	v, err := Scanner{}.Verify(context.Background(), dummyID+":"+dummySecret)
	if err == nil {
		t.Fatal("expected transient error on 429")
	}
	if v {
		t.Fatal("expected verified=false on 429")
	}
}

func TestVerify_NoSecretNoOp(t *testing.T) {
	// Id-only finding cannot be signed; verify must no-op without an HTTP call.
	v, err := Scanner{}.Verify(context.Background(), dummyID)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if v {
		t.Fatal("expected verified=false for id-only input")
	}
}

func TestFromData_VerifiesPair(t *testing.T) {
	withServer(t, http.StatusOK)
	body := "aliyun_access_key_id=" + dummyID + "\naliyun_access_key_secret=" + dummySecret + "\n"
	res, err := Scanner{}.FromData(context.Background(), true, []byte(body))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(res))
	}
	if !res[0].Verified {
		t.Fatalf("expected verified pair, got %+v", res[0])
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyID)
	if r == dummyID {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "LTAIabcd") {
		t.Fatalf("missing prefix: %q", r)
	}
}
