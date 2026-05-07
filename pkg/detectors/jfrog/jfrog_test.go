package jfrog

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const dummy = "cmVmdGtuOjAxOjE2OTk5OTk5OTk6QWJDZEVmR2hJaktsTW5PcFFyU3RVdldYWVo6QWJDZEVmR2hJaktsTW5PcFFyU3RVdldYWVowMTIzNDU2Nzg5"

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.JFrog {
		t.Fatalf("type mismatch")
	}
}

func TestKeywords(t *testing.T) {
	if got := (Scanner{}).Keywords(); len(got) == 0 {
		t.Fatal("keywords empty")
	}
}

func TestFromData_Positive(t *testing.T) {
	body := []byte("JFROG_ACCESS_TOKEN=" + dummy)
	res, err := Scanner{}.FromData(context.Background(), false, body)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1, got %d", len(res))
	}
}

func TestFromData_NoKeyword(t *testing.T) {
	res, _ := Scanner{}.FromData(context.Background(), false, []byte("noise=AbCdEf0123456789"))
	if len(res) != 0 {
		t.Fatalf("expected 0 without cmVmdGtuO prefix, got %d", len(res))
	}
}

func TestVerify_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+dummy {
			t.Errorf("auth mismatch: %q", r.Header.Get("Authorization"))
		}
		if !strings.HasSuffix(r.URL.Path, "/artifactory/api/system/ping") {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	v, err := Scanner{}.Verify(context.Background(), srv.URL+"|"+dummy)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !v {
		t.Fatal("expected verified=true")
	}
}

func TestVerify_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	v, _ := Scanner{}.Verify(context.Background(), srv.URL+"|"+dummy)
	if v {
		t.Fatal("expected verified=false")
	}
}

func TestVerify_TransportError(t *testing.T) {
	v, err := Scanner{}.Verify(context.Background(), "http://127.0.0.1:1|"+dummy)
	if err == nil {
		t.Fatal("expected transport error")
	}
	if v {
		t.Fatal("expected verified=false on transport error")
	}
}
