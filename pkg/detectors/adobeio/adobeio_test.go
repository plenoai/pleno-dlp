package adobeio

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const dummyKey = "abcdef0123456789abcdef0123456789"
const dummySecret = "p8e-AbCdEfGhIjKlMnOpQrStUvWxYz012345"

func TestFromData_Pair(t *testing.T) {
	body := "adobeio_client_id=" + dummyKey + "\nadobeio_client_secret=" + dummySecret
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyKey {
		t.Fatalf("key: %q", res[0].Raw)
	}
	if string(res[0].RawV2) != dummySecret {
		t.Fatalf("secret: %q", res[0].RawV2)
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := "id=" + dummyKey + "\nsecret=" + dummySecret
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0 without keyword, got %d", len(res))
	}
}

func TestFromData_KeyAlone_Skipped(t *testing.T) {
	// 32-hex without a paired secret is indistinguishable from md5.
	body := "adobeio_client_id=" + dummyKey
	res, _ := Scanner{}.FromData(context.Background(), false, []byte(body))
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.FormValue("client_id") != dummyKey {
			t.Errorf("client_id mismatch")
		}
		if r.FormValue("client_secret") != dummySecret {
			t.Errorf("client_secret mismatch")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := imsBase
	imsBase = srv.URL
	defer func() { imsBase = old }()

	v, err := Scanner{}.VerifyPair(context.Background(), dummyKey, dummySecret)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	old := imsBase
	imsBase = srv.URL
	defer func() { imsBase = old }()

	v, _ := Scanner{}.VerifyPair(context.Background(), dummyKey, dummySecret)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := imsBase
	imsBase = "http://127.0.0.1:1"
	defer func() { imsBase = old }()

	v, err := Scanner{}.VerifyPair(context.Background(), dummyKey, dummySecret)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
