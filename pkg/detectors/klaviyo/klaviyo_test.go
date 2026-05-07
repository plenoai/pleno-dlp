package klaviyo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dummyPK = "pk_0123456789abcdef0123456789abcdef0123"
const dummySK = "sk_0123456789abcdef0123456789abcdef0123"

func TestFromData_Private(t *testing.T) {
	res, err := Scanner{}.FromData(context.Background(), false, []byte("KLAVIYO_PRIVATE_API_KEY="+dummyPK))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
	if string(res[0].Raw) != dummyPK {
		t.Fatalf("raw mismatch: %q", res[0].Raw)
	}
}

func TestFromData_Site(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("KLAVIYO_SK="+dummySK))
	if len(res) != 1 {
		t.Fatalf("expected 1 sk hit, got %d", len(res))
	}
}

func TestFromData_NotStripeKey(t *testing.T) {
	// Stripe sk_live_… should not match Klaviyo's regex because the `_`
	// after `live` breaks the [A-Za-z0-9]{32,64} body.
	stripe := "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("STRIPE="+stripe))
	for _, r := range res {
		if string(r.Raw) == stripe {
			t.Fatalf("klaviyo detector should not match Stripe sk_live_ token, got %v", r)
		}
	}
}

func TestRedact(t *testing.T) {
	r := redact(dummyPK)
	if r == dummyPK {
		t.Fatal("redact didn't redact")
	}
	if !strings.HasPrefix(r, "pk_01234") {
		t.Fatalf("missing prefix: %q", r)
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Klaviyo-API-Key "+dummyPK {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyPK)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()

	v, _ := Scanner{}.Verify(context.Background(), dummyPK)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	old := apiBase
	apiBase = "http://127.0.0.1:1"
	defer func() { apiBase = old }()

	v, err := Scanner{}.Verify(context.Background(), dummyPK)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
