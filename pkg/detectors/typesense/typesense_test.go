package typesense

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// dummy is a 32-char alphanumeric value matching the documented Typesense
// key shape (Cloud Management API admin/search keys are 32 alnum chars).
// High enough entropy (~4.6) to clear the 3.5 floor. Not a real key.
const dummy = "cBKqFPEcGRAS7RIKi3h3FuJbj4Q9Rprk"

// lowEntropyGeneric is a 32-char alnum run that clears the length regex and
// sits next to the keyword but is structured/low-entropy — it must be
// rejected by the entropy floor (regression for the FP shape we now cull).
const lowEntropyGeneric = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.Typesense {
		t.Fatal("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Found(t *testing.T) {
	body := []byte("TYPESENSE_API_KEY=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) == 0 {
		t.Fatal("expected >=1")
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	body := []byte("UNRELATED=" + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0, got %d", len(res))
	}
}

func TestFromData_LowEntropyRejected(t *testing.T) {
	// Armed by the keyword but the candidate is a structured low-entropy
	// 32-char run: must be culled by the entropy floor, not surfaced.
	body := []byte("TYPESENSE_API_KEY=" + lowEntropyGeneric)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (low-entropy FP), got %d", len(res))
	}
}

func TestFromData_WrongLengthRejected(t *testing.T) {
	// 33-char alnum next to the keyword: not the documented 32-char shape,
	// so the pinned-length regex must not match it.
	body := []byte("TYPESENSE_API_KEY=" + dummy + "X")
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (length mismatch), got %d", len(res))
	}
}

func TestFromData_BareKeywordNoArm(t *testing.T) {
	// A bare "typesense" substring (host/docs/package mention) without an
	// assignment-style reference must no longer arm a generic 32-char token.
	body := []byte("see typesense.org for docs " + dummy)
	res, _ := Scanner{}.FromData(context.Background(), false, body)
	if len(res) != 0 {
		t.Fatalf("expected 0 (bare keyword, no arm), got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-TYPESENSE-API-KEY") != dummy {
			t.Errorf("missing header")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, err := Scanner{}.Verify(context.Background(), dummy)
	if err != nil || !v {
		t.Fatalf("err=%v v=%v", err, v)
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	old := apiBase
	apiBase = srv.URL
	defer func() { apiBase = old }()
	v, _ := Scanner{}.Verify(context.Background(), dummy)
	if v {
		t.Fatal("expected verified=false")
	}
}
